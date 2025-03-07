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

type WSClientState struct {
	tcpConn    net.Conn
	wsConn     *common.WebsocketConn
	tcpConnNum int
}

func (wcs WSClientState) String() string {
	return fmt.Sprintf("%s <-> [tcp-%d] [%s]",
		wcs.wsConn.String(), wcs.tcpConnNum, wcs.tcpConn.RemoteAddr().String())
}

type WSClient struct {
	recvAddr *net.TCPAddr
	destAddr string

	recvListener *net.TCPListener
	recvState    map[net.Conn]*WSClientState
	tcpConnNum   int
	wsConnNum    int

	mu sync.RWMutex
}

func NewWSClient(recvAddr, destAddr string) (*WSClient, error) {
	uRecvAddr, err := net.ResolveTCPAddr("tcp", recvAddr)
	if err != nil {
		return nil, err
	}

	listener, err := net.ListenTCP("tcp", uRecvAddr)
	if err != nil {
		return nil, err
	}

	return &WSClient{
		recvAddr:     uRecvAddr,
		destAddr:     destAddr,
		recvListener: listener,
		recvState:    map[net.Conn]*WSClientState{},
	}, nil
}

func (wsc *WSClient) RemoveConnection(conn *common.WebsocketConn) {
	wsc.mu.Lock()

	for k, v := range wsc.recvState {
		if v.wsConn == conn {
			delete(wsc.recvState, k)

			v.tcpConn.Close()
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
		conns = append(conns, v.wsConn)
	}
	return conns
}

func (wsc *WSClient) ReadFromWS(clientState *WSClientState) {
	defer wsc.RemoveConnection(clientState.wsConn)

	log.Infof("Reading from WS->TCP %s", clientState.String())
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

		if _, err := io.CopyBuffer(clientState.tcpConn, rdr, buf[0:]); err != nil {
			log.Warnf("Error reading from WS to TCP: %v: %v", clientState, err)
			break
		}
	}
}

func (wsc *WSClient) WriteToWS(clientState *WSClientState) {
	defer wsc.RemoveConnection(clientState.wsConn)

	log.Infof("Writing from TCP->WS %s", clientState.String())
	var buf [common.MaxMessageSize]byte
	for {
		n, err := clientState.tcpConn.Read(buf[0:])
		if err != nil {
			log.Warnf("Failed to read from %v: %s", clientState.String(), err)
			break
		}

		wc, err := clientState.wsConn.Conn.NextWriter(websocket.BinaryMessage)
		if err != nil {
			log.Warnf("Failed to create writer for %v: %v", clientState.String(), err)
			break
		} else if _, err = wc.Write(buf[:n]); err != nil {
			log.Warnf("Failed to write to %v: %v", clientState.String(), err)
			wc.Close()
			break
		} else if err = wc.Close(); err != nil {
			log.Warnf("Failed to close writer for %v: %v", clientState.String(), err)
		}
	}
}

func (wsc *WSClient) ManageConn(clConn net.Conn) error {
	log.Infof("Accepting new connection from %v to %v", clConn.RemoteAddr(), wsc.destAddr)
	token, err := totp.GenerateCode(common.CliKey, time.Now())
	if err != nil {
		return fmt.Errorf("Failed to generate TOTP token: %v", err)
	}
	login, err := json.Marshal(common.LoginMessage{
		AsReceiver: false,
		Token:      token,
	})
	if err != nil {
		return fmt.Errorf("Failed to serialise login message: %v", err)
	}

	conn, _, err := websocket.DefaultDialer.Dial(wsc.destAddr, http.Header{})
	if err != nil {
		return fmt.Errorf("Failed to connect websocket: %v", err)
	}

	conn.SetWriteDeadline(time.Now().Add(common.RWTimeout))
	if err = conn.WriteMessage(websocket.TextMessage, login); err != nil {
		conn.Close()
		return fmt.Errorf("Failed to send login: %v", err)
	}

	wsc.wsConnNum++
	wsc.tcpConnNum++

	wsc.mu.Lock()
	if wsc.recvState[clConn] != nil {
		return fmt.Errorf("SHOULD NOT HAPPEN: RECV STATE WAS NOT NIL: %v, %v", clConn, wsc.recvState[clConn])
	}

	clientState := &WSClientState{
		tcpConn:    clConn,
		wsConn:     common.NewWebsocketConn(conn, "[ws-%d]", wsc.wsConnNum),
		tcpConnNum: wsc.tcpConnNum,
	}
	wsc.recvState[clConn] = clientState
	wsc.mu.Unlock()

	common.SetPongHandler(clientState.wsConn)

	go wsc.ReadFromWS(clientState)
	go wsc.WriteToWS(clientState)
	return nil
}

func (wsc *WSClient) Listen() {
	log.Infof("Listening on %v", wsc.recvAddr)
	for {
		conn, err := wsc.recvListener.Accept()
		if err != nil {
			log.Warnf("Error accepting TCP conn: %v", err)
			continue
		}

		go func() {
			err := wsc.ManageConn(conn)
			if err != nil {
				log.Warnf("Failed to manage conn: %v", err)
			}
		}()
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
