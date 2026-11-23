package service

import (
	"os"
	"os/user"
	"path/filepath"
	"unicode/utf16"
)

// Install registers a scheduled task that runs at the person's logon, as
// that person, and starts it now. The task is defined in XML: the defaults
// of schtasks stop a task after three days and skip it on battery.
func Install(s Spec) (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp("", "tender-task-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	xmlPath := filepath.Join(dir, "task.xml")
	if err := os.WriteFile(xmlPath, utf16LE(TaskXML(s, u.Username)), 0o600); err != nil {
		return "", err
	}
	_ = run("schtasks", "/End", "/TN", Task)
	if err := run("schtasks", "/Create", "/F", "/TN", Task, "/XML", xmlPath); err != nil {
		return "", err
	}
	if err := run("schtasks", "/Run", "/TN", Task); err != nil {
		return "", err
	}
	return `scheduled task \` + Task, nil
}

// Uninstall stops the task and deletes it.
func Uninstall() (string, error) {
	_ = run("schtasks", "/End", "/TN", Task)
	if err := run("schtasks", "/Delete", "/F", "/TN", Task); err != nil {
		return "", err
	}
	return `scheduled task \` + Task, nil
}

// utf16LE is how schtasks wants its XML: UTF-16 with a byte order mark.
func utf16LE(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := []byte{0xFF, 0xFE}
	for _, u := range units {
		out = append(out, byte(u), byte(u>>8))
	}
	return out
}
