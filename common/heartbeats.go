package common

import (
	"time"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

type ConnectionManager interface {
	GetConnections() []*WebsocketConn
	RemoveConnection(conn *WebsocketConn)
}

func ManageHeartbeats(cm ConnectionManager) {
	for {
		conns := cm.GetConnections()

		for _, conn := range conns {
			log.Debugf("Sending ping to %v", conn)
			err := conn.Conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(RWTimeout))
			if err != nil {
				log.Warnf("Failed to write ping to %v: %v", conn, err)
				cm.RemoveConnection(conn)
			}
		}
		time.Sleep(HBTimeout)
	}
}

func SetPongHandler(conn *websocket.Conn) {
	conn.SetPongHandler(func(string) error {
		deadline := time.Now().Add(RWTimeout)
		if err := conn.SetWriteDeadline(deadline); err != nil {
			return err
		}
		return conn.SetReadDeadline(deadline)
	})
}
