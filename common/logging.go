package common

import (
	log "github.com/sirupsen/logrus"
)

func InitLogging(forceColours, disableTimestamp bool) {
	InitSyslog()

	log.SetFormatter(&log.TextFormatter{
		ForceColors:      forceColours,
		DisableTimestamp: disableTimestamp,
	})
}
