package common

import (
	"fmt"
	"log/syslog"
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	logrus_syslog "github.com/sirupsen/logrus/hooks/syslog"
)

func GetLocalTime() (*time.Location, error) {
	if _, err := exec.LookPath("nvram"); err != nil || runtime.GOOS != "linux" || runtime.GOARCH != "arm" {
		return time.Local, nil
	}

	cmd := exec.Command("date", "-R")
	out, err := cmd.Output()
	if err != nil {
		return time.Local, err
	}

	tm, err := time.Parse(time.RFC1123Z, strings.TrimSpace(string(out)))
	if err != nil {
		return time.Local, err
	}

	_, off := tm.Zone()
	return time.FixedZone(tm.Format("UTC-07:00"), off), nil
}

func InitSyslog() {
	hook, err := logrus_syslog.NewSyslogHook("", "", syslog.LOG_INFO, "wsrelay")
	if err != nil {
		log.Info("Unable to connect to local syslog daemon: %v", err)
	} else {
		time.Local, err = GetLocalTime()
		if err != nil {
			log.Info("Unable to configure local time: %v", err)
		}
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
