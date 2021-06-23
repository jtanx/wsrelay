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

const maxConns = 10

type wsConnPair struct {
	wsConn        *common.WebsocketConn
	clientConn    *net.UDPConn
	clientConnNum int
}

func (wcp wsConnPair) String() string {
	if wcp.clientConn == nil {
		return fmt.Sprintf("%s (unpaired)", wcp.wsConn.String())
	}
	return fmt.Sprintf("%s <-> [udp-%d] [%s->%s]",
		wcp.wsConn.String(), wcp.clientConnNum,
		wcp.clientConn.LocalAddr().String(), wcp.clientConn.RemoteAddr().String())
}

func NewWSConnPair(wsConn *websocket.Conn, wsDesc string, wsDescArgs ...interface{}) *wsConnPair {
	return &wsConnPair{
		wsConn: common.NewWebsocketConn(wsConn, wsDesc, wsDescArgs...),
	}
}

type WSReceiver struct {
	destAddr *net.UDPAddr
	srvAddr  string

	numActiveConns int
	udpConnNum     int
	wsConnNum      int
	conns          []*wsConnPair
	mu             sync.Mutex
	cond           *sync.Cond
}

func NewWSReceiver(destAddr, srvAddr string) (*WSReceiver, error) {
	uDestAddr, err := net.ResolveUDPAddr("udp", destAddr)
	if err != nil {
		return nil, err
	}

	recv := &WSReceiver{
		destAddr: uDestAddr,
		srvAddr:  srvAddr,
	}
	recv.cond = sync.NewCond(&recv.mu)
	return recv, nil
}

func (wsr *WSReceiver) RemoveConnection(conn *common.WebsocketConn) {
	wsr.mu.Lock()

	for i, c := range wsr.conns {
		if c.wsConn == conn {
			wsr.conns = append(wsr.conns[:i], wsr.conns[i+1:]...)
			if c.clientConn != nil {
				wsr.numActiveConns--
				c.clientConn.Close()
			}
			c.wsConn.Conn.Close()
			log.Infof("Removed conn (active %d/%d): %v",
				wsr.numActiveConns, len(wsr.conns), c)
		}
	}

	wsr.mu.Unlock()
	wsr.cond.Broadcast()
}

func (wsr *WSReceiver) GetConnections() []*common.WebsocketConn {
	wsr.mu.Lock()
	defer wsr.mu.Unlock()
	conns := make([]*common.WebsocketConn, len(wsr.conns))
	for i, c := range wsr.conns {
		conns[i] = c.wsConn
	}
	return conns
}

func (wsr *WSReceiver) ManageConnection(conn *wsConnPair) {
	defer wsr.RemoveConnection(conn.wsConn)

	log.Infof("Managing connection %v", conn)
	var buf [common.MaxMessageSize]byte
	for {
		mt, rdr, err := conn.wsConn.Conn.NextReader()
		if err != nil {
			log.Warnf("Failed to read from WS %v: %v", conn.wsConn, err)
			break
		} else if mt != websocket.BinaryMessage {
			log.Warnf("Got unexpected message from WS %v: %v", conn.wsConn, mt)
			break
		}

		if conn.clientConn == nil {
			conn.clientConn, err = net.DialUDP("udp", nil, wsr.destAddr)
			if err != nil {
				log.Warnf("Could not open destination connection: %v", err)
				break
			}

			wsr.mu.Lock()
			wsr.numActiveConns++
			wsr.udpConnNum++
			conn.clientConnNum = wsr.udpConnNum
			wsr.mu.Unlock()
			wsr.cond.Broadcast()

			log.Infof("Paired connection: %v", conn)

			go func() {
				var rdBuf [common.MaxMessageSize]byte
				defer wsr.RemoveConnection(conn.wsConn)

				for {
					n, err := conn.clientConn.Read(rdBuf[0:])
					if err != nil {
						log.Warnf("Failed to read from UDP conn: %v: %v", conn, err)
						break
					}

					wc, err := conn.wsConn.Conn.NextWriter(websocket.BinaryMessage)
					if err != nil {
						log.Warnf("Failed to create WS writer: %v: %v", conn, err)
						break
					}

					_, err = wc.Write(rdBuf[:n])
					wc.Close()

					if err != nil {
						log.Warnf("Failed to write to websocket: %v: %v", conn, err)
						break
					}
				}
			}()
		}

		if _, err := io.CopyBuffer(conn.clientConn, rdr, buf[0:]); err != nil {
			log.Warnf("Error copying from websocket to conn: %v: %v", conn, err)
			break
		}
	}
}

func (wsr *WSReceiver) AddConnection() error {
	log.Infof("Connecting to %s", wsr.srvAddr)

	token, err := totp.GenerateCode(common.SrvKey, time.Now())
	if err != nil {
		return fmt.Errorf("Failed to generate TOTP token: %v", err)
	}
	login, err := json.Marshal(common.LoginMessage{
		AsReceiver: true,
		Token:      token,
	})
	if err != nil {
		return fmt.Errorf("Failed to serialise login message: %v", err)
	}
	conn, _, err := websocket.DefaultDialer.Dial(wsr.srvAddr, http.Header{})
	if err != nil {
		return fmt.Errorf("Failed to connect websocket: %v", err)
	}

	common.SetPongHandler(conn)
	conn.SetWriteDeadline(time.Now().Add(common.RWTimeout))
	if err = conn.WriteMessage(websocket.TextMessage, login); err != nil {
		conn.Close()
		return fmt.Errorf("Failed to send login: %v", err)
	}

	wsr.mu.Lock()
	wsr.wsConnNum++
	connPair := NewWSConnPair(conn, "[ws-%d]", wsr.wsConnNum)
	wsr.conns = append(wsr.conns, connPair)
	wsr.mu.Unlock()

	go wsr.ManageConnection(connPair)
	return nil
}

func (wsr *WSReceiver) ManageConnections() {
	for {
		wsr.cond.L.Lock()
		for (len(wsr.conns) > 0 && len(wsr.conns) > wsr.numActiveConns) || wsr.numActiveConns >= maxConns {
			log.Infof("Current connections satisfied, waiting (num WS %v, active %v, max %v)",
				len(wsr.conns), wsr.numActiveConns, maxConns)
			wsr.cond.Wait()
		}
		wsr.cond.L.Unlock()

		if err := wsr.AddConnection(); err != nil {
			log.Warnf("Failed to add connection, sleeping for 15s: %v", err)
			time.Sleep(15 * time.Second)
		}
	}
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s connect-addr ws-addr\nExample: %s 127.0.0.1:1235 ws://127.0.0.1:5678/relay\n",
			os.Args[0], os.Args[0])
		os.Exit(1)
	}

	common.InitLogging(false, true)
	log.Info("WSRelay Receiver: GitRev: ", common.GitRev)
	if err := common.InitUid(); err != nil {
		log.Errorf("Failed to set uid: %v", err)
		return
	}

	receiver, err := NewWSReceiver(os.Args[1], os.Args[2])
	if err != nil {
		log.Errorf("Failed to make receiver: %v", err)
		return
	}
	go common.ManageHeartbeats(receiver)
	receiver.ManageConnections()
}
