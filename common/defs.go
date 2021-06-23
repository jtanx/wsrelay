package common

import (
	"fmt"
	"time"

	"github.com/gorilla/websocket"
)

//go:generate go run ./gendef

const (
	MaxMessageSize = 8192
	RWTimeout      = 60 * time.Second
	HBTimeout      = RWTimeout / 2
)

type LoginMessage struct {
	AsReceiver bool   `json:"as_receiver"`
	Token      string `json:"token"`
}

type WebsocketConn struct {
	Conn *websocket.Conn
	Desc string
}

func (wsc WebsocketConn) String() string {
	return fmt.Sprintf("%s [%s->%s]",
		wsc.Desc, wsc.Conn.LocalAddr().String(), wsc.Conn.RemoteAddr().String())
}

func NewWebsocketConn(conn *websocket.Conn, descFmt string, args ...interface{}) *WebsocketConn {
	return &WebsocketConn{
		Conn: conn,
		Desc: fmt.Sprintf(descFmt, args...),
	}
}
