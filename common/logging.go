package common

import (
	log "github.com/sirupsen/logrus"
)

func InitLogging(forceColours, disableTimestamp bool) {
	InitSyslog()

	// log.SetLevel(log.DebugLevel)
	log.SetFormatter(&log.TextFormatter{
		ForceColors:      forceColours,
		DisableTimestamp: disableTimestamp,
	})
}
