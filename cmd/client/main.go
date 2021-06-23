package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/jtanx/wsrelay/common"
	"github.com/pquerna/otp/totp"
	log "github.com/sirupsen/logrus"
)

type UDPAddrKey struct {
	IP   string
	Port int
}

func NewUDPAddrKey(addr *net.UDPAddr) UDPAddrKey {
	return UDPAddrKey{
		IP:   string(addr.IP),
		Port: addr.Port,
	}
}

type WSClientState struct {
	addr       *net.UDPAddr
	wsConn     *common.WebsocketConn
	udpConnNum int
	wasActive  bool
}

func (wcs WSClientState) String() string {
	return fmt.Sprintf("%s <-> [udp-%d] [%s]",
		wcs.wsConn.String(), wcs.udpConnNum, wcs.addr.String())
}

type WSClient struct {
	recvAddr *net.UDPAddr
	destAddr string

	recvConn   *net.UDPConn
	recvState  map[UDPAddrKey]*WSClientState
	udpConnNum int
	wsConnNum  int

	mu sync.RWMutex
}

func NewWSClient(recvAddr, destAddr string) (*WSClient, error) {
	uRecvAddr, err := net.ResolveUDPAddr("udp", recvAddr)
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenUDP("udp", uRecvAddr)
	if err != nil {
		return nil, err
	}

	return &WSClient{
		recvAddr:  uRecvAddr,
		destAddr:  destAddr,
		recvConn:  conn,
		recvState: map[UDPAddrKey]*WSClientState{},
	}, nil
}

func (wsc *WSClient) RemoveConnection(conn *common.WebsocketConn) {
	wsc.mu.Lock()

	for k, v := range wsc.recvState {
		if v.wsConn == conn {
			delete(wsc.recvState, k)
			conn.Conn.Close()

			log.Infof("Removed conn %s, num conns %v",
				v.String(), len(wsc.recvState))
		}
	}

	wsc.mu.Unlock()
}

func (wsc *WSClient) GetConnections() []*common.WebsocketConn {
	wsc.mu.RLock()
	defer wsc.mu.RUnlock()
	conns := make([]*common.WebsocketConn, 0, len(wsc.recvState))
	for _, v := range wsc.recvState {
		if v.wasActive {
			conns = append(conns, v.wsConn)
			v.wasActive = false // not locked around this...
		} else {
			log.Infof("Excluding %s from active conns", v.String())
		}
	}
	return conns
}

func (wsc *WSClient) RunClientConnection(clientState *WSClientState) {
	defer wsc.RemoveConnection(clientState.wsConn)

	log.Infof("Managing connection %s", clientState.String())
	var buf [common.MaxMessageSize]byte
	for {
		mt, rdr, err := clientState.wsConn.Conn.NextReader()
		if err != nil {
			log.Warnf("Failed to read from %v: %s", clientState.wsConn, err)
			break
		} else if mt != websocket.BinaryMessage {
			log.Warnf("Got unexpected message from %v: %v", clientState.wsConn, mt)
			break
		}

		var n int
		for err == nil {
			n, err = rdr.Read(buf[0:])
			if err == nil {
				_, err = wsc.recvConn.WriteToUDP(buf[:n], clientState.addr)
			}
		}
		if err != nil && err != io.EOF {
			log.Warnf("Error reading from WS to UDP: %v: %v", clientState, err)
			break
		}
	}
}

func (wsc *WSClient) GetClientState(clientAddr *net.UDPAddr) (*WSClientState, error) {
	addrKey := NewUDPAddrKey(clientAddr)

	wsc.mu.RLock()
	clientState := wsc.recvState[addrKey]
	wsc.mu.RUnlock()

	if clientState == nil {
		return func() (*WSClientState, error) {
			wsc.mu.Lock()
			defer wsc.mu.Unlock()

			clientState := wsc.recvState[addrKey]
			if clientState != nil {
				return clientState, nil
			}

			log.Infof("Accepting new connection from %v to %v", clientAddr, wsc.destAddr)
			token, err := totp.GenerateCode(common.CliKey, time.Now())
			if err != nil {
				return nil, fmt.Errorf("Failed to generate TOTP token: %v", err)
			}
			login, err := json.Marshal(common.LoginMessage{
				AsReceiver: false,
				Token:      token,
			})
			if err != nil {
				return nil, fmt.Errorf("Failed to serialise login message: %v", err)
			}

			conn, _, err := websocket.DefaultDialer.Dial(wsc.destAddr, http.Header{})
			if err != nil {
				return nil, fmt.Errorf("Failed to connect websocket: %v", err)
			}

			common.SetPongHandler(conn)
			conn.SetWriteDeadline(time.Now().Add(common.RWTimeout))
			if err = conn.WriteMessage(websocket.TextMessage, login); err != nil {
				conn.Close()
				return nil, fmt.Errorf("Failed to send login: %v", err)
			}

			wsc.wsConnNum++
			wsc.udpConnNum++
			clientState = &WSClientState{
				addr:       clientAddr,
				wsConn:     common.NewWebsocketConn(conn, "[ws-%d]", wsc.wsConnNum),
				udpConnNum: wsc.udpConnNum,
				wasActive:  true,
			}

			wsc.recvState[addrKey] = clientState
			go wsc.RunClientConnection(clientState)

			return clientState, nil
		}()
	}

	return clientState, nil
}

func (wsc *WSClient) Listen() {
	log.Infof("Listening on %v", wsc.recvAddr)
	buf := make([]byte, common.MaxMessageSize)
	for {
		n, clAddr, err := wsc.recvConn.ReadFromUDP(buf)
		if err != nil {
			log.Warnf("Error reading from UDP listening port: %v", err)
			continue
		}

		if clAddr.Port == wsc.recvAddr.Port && clAddr.IP.Equal(wsc.recvAddr.IP) {
			log.Errorf("Received data on our bound port: %v", clAddr)
			return
		}

		clientState, err := wsc.GetClientState(clAddr)
		if err != nil {
			log.Warnf("Error fetching client state: %v", err)
			continue
		}

		log.Debugf("Recv bytes srv %v %v", clAddr, n)
		clientState.wasActive = true
		wc, err := clientState.wsConn.Conn.NextWriter(websocket.BinaryMessage)
		if err != nil {
			log.Warnf("Failed to make WS writer: %v: %v", clientState, err)
			wsc.RemoveConnection(clientState.wsConn)
			continue
		}

		_, err = wc.Write(buf[:n])
		wc.Close()
		if err != nil {
			log.Warnf("Failed to write to WS: %v: %v", clientState, err)
			wsc.RemoveConnection(clientState.wsConn)
			continue
		}
	}
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s listen-addr ws-addr\nExample: %s 127.0.0.1:1234 ws://127.0.0.1:5678/relay\n",
			os.Args[0], os.Args[0])
		os.Exit(1)
	}

	common.InitLogging(true, false)
	log.Info("WSRelay Client: GitRev: ", common.GitRev)

	client, err := NewWSClient(os.Args[1], os.Args[2])
	if err != nil {
		log.Errorf("Failed to make WS client: %v", err)
		return
	}
	go common.ManageHeartbeats(client)
	client.Listen()
}
