package common

import (
	"fmt"
	"log/syslog"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	logrus_syslog "github.com/sirupsen/logrus/hooks/syslog"
)

// GetLocalTime parses tz info in the posix time format, ignoring DST offsets
func GetLocalTime() (*time.Location, error) {
	cmd := exec.Command("nvram", "get", "tm_tz")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return time.Local, err
	}

	rout := strings.TrimSpace(string(out))
	for i, c := range rout {
		if c == '-' || (c >= '0' && c <= '9') {
			var j int
			for j = i + 1; j < len(rout); j++ {
				if rout[j] != '.' && !(rout[j] >= '0' && rout[j] <= '9') {
					break
				}
			}

			n, err := strconv.ParseFloat(rout[i:j], 64)
			if err != nil {
				return time.Local, err
			}

			name := rout[:i]
			if name == "UTC" {
				if rout[i] == '-' {
					name = rout[:i] + "+" + rout[i+1:j]
				} else {
					name = rout[:i] + "-" + rout[i:j]
				}
			}

			off := int(-n * 60 * 60)
			return time.FixedZone(name, off), nil
		}
	}

	return time.Local, fmt.Errorf("unable to parse %v", rout)
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
