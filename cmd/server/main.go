package main

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/jtanx/wsrelay/common"
	"github.com/julienschmidt/httprouter"
	"github.com/pquerna/otp/totp"

	log "github.com/sirupsen/logrus"
)

type WSRelay struct {
	upgrader   websocket.Upgrader
	conns      []*common.WebsocketConn
	freeConns  []*common.WebsocketConn
	mu         sync.RWMutex
	srvCounter int
	cliCounter int
}

func NewWSRelay() *WSRelay {
	return &WSRelay{
		upgrader: websocket.Upgrader{
			HandshakeTimeout: common.RWTimeout,
		},
	}
}

func (wsr *WSRelay) GetConnections() []*common.WebsocketConn {
	wsr.mu.RLock()
	defer wsr.mu.RUnlock()
	return wsr.conns
}

func (wsr *WSRelay) RemoveConnection(conn *common.WebsocketConn) {
	wsr.mu.Lock()
	defer wsr.mu.Unlock()

	for i, c := range wsr.conns {
		if c == conn {
			wsr.conns = append(wsr.conns[:i], wsr.conns[i+1:]...)
			err := conn.Conn.Close()
			log.Infof("Removed conn %v, err: %v", conn, err)
		}
	}
}

func (wsr *WSRelay) RelayReads(from *common.WebsocketConn, to *common.WebsocketConn) {
	var buf [common.MaxMessageSize]byte

	defer func() {
		log.Infof("Cleaning up connection pair: %v and %v", from, to)
		wsr.RemoveConnection(from)
		wsr.RemoveConnection(to)
	}()

	for {
		mt, rdr, err := from.Conn.NextReader()
		if err != nil {
			log.Warnf("Failed to read from %v: %v", from, err)
			break
		} else if mt != websocket.BinaryMessage {
			log.Warnf("Got unexptected message from %v: %v", from, mt)
			break
		}

		wc, err := to.Conn.NextWriter(websocket.BinaryMessage)
		if err != nil {
			log.Warnf("Failed to open writer to %v: %v", to, err)
			break
		}

		if _, err = io.CopyBuffer(wc, rdr, buf[0:]); err != nil {
			log.Warnf("Failed to copy from %v to %v: %v",
				from, to, err)
			break
		}

		err = wc.Close()
		if err != nil {
			log.Warnf("Error while closing writer to %v: %v", to, err)
		}
	}
}

func (wsr *WSRelay) Serve(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	conn, err := wsr.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Warnf("Failed to upgrade connection: %v", err)
		return
	} else if err = conn.SetReadDeadline(time.Now().Add(common.RWTimeout)); err != nil {
		log.Warnf("Failed to set read deadline: %v", err)
		conn.Close()
		return
	}

	log.Infof("Received connection from %v", conn.RemoteAddr().String())
	msgType, data, err := conn.ReadMessage()
	if err != nil {
		log.Warnf("Failed to read login: %v", err)
		conn.Close()
		return
	} else if msgType != websocket.TextMessage {
		log.Warnf("Bad request, login message was not text but: %v", msgType)
		conn.Close()
		return
	}

	var msg common.LoginMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		log.Warnf("Bad request, could not decode login: %v", err)
		conn.Close()
		return
	}

	common.SetPongHandler(conn)

	wsr.mu.Lock()
	defer wsr.mu.Unlock()

	if msg.AsReceiver {
		if !totp.Validate(msg.Token, common.SrvKey) {
			log.Warnf("TOTP validation failed for server key: %v", msg.Token)
			conn.Close()
			return
		}

		wsr.srvCounter++
		wsConn := common.NewWebsocketConn(conn, "[srv-%d]", wsr.srvCounter)
		log.Infof("Accepted receiver conn: %v", wsConn)

		wsr.conns = append(wsr.conns, wsConn)
		wsr.freeConns = append(wsr.freeConns, wsConn)
	} else {
		if !totp.Validate(msg.Token, common.CliKey) {
			log.Warnf("TOTP validation failed for client key: %v", msg.Token)
			conn.Close()
			return
		} else if len(wsr.freeConns) == 0 {
			log.Warnf("No free conns are available, dropping client conn")
			conn.Close()
			return
		}

		wsr.cliCounter++
		srvConn := wsr.freeConns[0]
		wsr.freeConns = wsr.freeConns[1:]
		wsConn := common.NewWebsocketConn(conn, "[cli-%d]", wsr.cliCounter)

		wsr.conns = append(wsr.conns, wsConn)
		log.Infof("Accepted client conn: %v paired with %v",
			srvConn, wsConn)

		go wsr.RelayReads(srvConn, wsConn)
		go wsr.RelayReads(wsConn, srvConn)
	}
}

func getHandler(relay *WSRelay) http.Handler {
	router := httprouter.New()
	router.RedirectFixedPath = true
	router.GET("/relay", relay.Serve)
	return router
}

func main() {
	common.InitLogging(false, false)
	log.Info("WSRelay Server: GitRev: ", common.GitRev)

	relay := NewWSRelay()
	go common.ManageHeartbeats(relay)

	addr := os.Getenv("HTTP_PLATFORM_PORT")
	if addr == "" {
		addr = ":5050"
	} else {
		addr = ":" + addr
	}

	log.Infof("Started [%s:%d] with address %s", os.Args[0], os.Getpid(), addr)
	server := http.Server{
		Addr:    addr,
		Handler: getHandler(relay),
	}
	err := server.ListenAndServe()
	log.Errorf("Error listening: %v", err)
}
