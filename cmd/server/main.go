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
	conns      map[string][]*common.WebsocketConn
	freeConns  map[string][]*common.WebsocketConn
	mu         sync.RWMutex
	srvCounter int
	cliCounter int
}

func NewWSRelay() *WSRelay {
	return &WSRelay{
		upgrader: websocket.Upgrader{
			HandshakeTimeout: common.RWTimeout,
		},
		conns:     make(map[string][]*common.WebsocketConn),
		freeConns: make(map[string][]*common.WebsocketConn),
	}
}

func (wsr *WSRelay) GetConnections() []*common.WebsocketConn {
	wsr.mu.RLock()
	defer wsr.mu.RUnlock()

	var allConnections []*common.WebsocketConn
	for _, connList := range wsr.conns {
		allConnections = append(allConnections, connList...)
	}
	return allConnections
}

func (wsr *WSRelay) RemoveConnection(conn *common.WebsocketConn) {
	wsr.mu.Lock()
	defer wsr.mu.Unlock()

	for fn, fc := range wsr.freeConns {
		for i, c := range fc {
			if c == conn {
				wsr.freeConns[fn] = append(wsr.freeConns[fn][:i], wsr.freeConns[fn][i+1:]...)
				log.Infof("Removed conn from free list: %v", conn)
			}
		}
	}

	for cn, cc := range wsr.conns {
		for i, c := range cc {
			if c == conn {
				wsr.conns[cn] = append(wsr.conns[cn][:i], wsr.conns[cn][i+1:]...)
				err := conn.Conn.Close()
				log.Infof("Removed conn %v, err: %v", conn, err)
			}
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

	path := ps.ByName("path")
	log.Infof("Received connection from %v (path %v, headers %v)",
		conn.RemoteAddr().String(), path, r.Header)
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

		common.SetPongHandler(wsConn)
		wsr.conns[path] = append(wsr.conns[path], wsConn)
		wsr.freeConns[path] = append(wsr.freeConns[path], wsConn)
	} else {
		if !totp.Validate(msg.Token, common.CliKey) {
			log.Warnf("TOTP validation failed for client key: %v", msg.Token)
			conn.Close()
			return
		} else if len(wsr.freeConns[path]) == 0 {
			log.Warnf("No free conns are available, dropping client conn")
			conn.Close()
			return
		}

		wsr.cliCounter++
		srvConn := wsr.freeConns[path][0]
		wsr.freeConns[path] = wsr.freeConns[path][1:]
		wsConn := common.NewWebsocketConn(conn, "[cli-%d]", wsr.cliCounter)
		log.Infof("Accepted client conn: %v paired with %v",
			srvConn, wsConn)

		// Need to re-set the read deadline on the server connection as
		// we haven't been reading off it in the mean time
		srvConn.Conn.SetReadDeadline(time.Now().Add(common.RWTimeout))
		common.SetPongHandler(wsConn)
		wsr.conns[path] = append(wsr.conns[path], wsConn)

		go wsr.RelayReads(srvConn, wsConn)
		go wsr.RelayReads(wsConn, srvConn)
	}
}

func getHandler(relay *WSRelay) http.Handler {
	router := httprouter.New()
	router.RedirectFixedPath = true
	router.GET("/relay", relay.Serve)
	router.GET("/relay/*path", relay.Serve)
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
