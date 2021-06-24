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

func SetPongHandler(conn *WebsocketConn) {
	conn.Conn.SetPongHandler(func(string) error {
		deadline := time.Now().Add(RWTimeout)
		log.Debugf("PONG on %v, going to set deadline to %v", conn, deadline)
		if err := conn.Conn.SetWriteDeadline(deadline); err != nil {
			return err
		} else if err = conn.Conn.SetReadDeadline(deadline); err != nil {
			return err
		}
		log.Debugf("Set read/write deadline to %v: %v", deadline, conn)
		return nil
	})
}
