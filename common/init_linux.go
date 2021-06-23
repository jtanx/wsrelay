package common

import (
	"fmt"
	"log/syslog"
	"os/user"
	"strconv"
	"syscall"

	log "github.com/sirupsen/logrus"
	logrus_syslog "github.com/sirupsen/logrus/hooks/syslog"
)

func InitSyslog() {
	hook, err := logrus_syslog.NewSyslogHook("", "", syslog.LOG_INFO, "wsrelay")
	if err != nil {
		log.Info("Unable to connect to local syslog daemon: %v", err)
	} else {
		log.AddHook(hook)
	}
}

func InitUid() error {
	if user, err := user.Lookup("nobody"); err != nil {
		return fmt.Errorf("Error finding user 'nobody': %v", err)
	} else if gid, err := strconv.ParseInt(user.Gid, 10, 0); err != nil {
		return fmt.Errorf("Error parsing gid: %s: %v", user.Gid, err)
	} else if uid, err := strconv.ParseInt(user.Uid, 10, 0); err != nil {
		return fmt.Errorf("Error parsing uid: %s: %v", user.Uid, err)
	} else if err = syscall.Setgid(int(gid)); err != nil {
		return fmt.Errorf("Failed to set gid to %d: %v", gid, err)
	} else if err = syscall.Setuid(int(uid)); err != nil {
		return fmt.Errorf("Failed to set uid to %d: %v", uid, err)
	} else {
		log.Infof("Set uid/gid to nobody (%d:%d)", uid, gid)
	}
	return nil
}
