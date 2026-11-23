package service

import (
	"os"
	"path/filepath"
)

func unitPath() (string, error) {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "systemd", "user", Unit), nil
}

// Install writes the systemd user unit, enables it, and (re)starts it.
func Install(s Spec) (string, error) {
	path, err := unitPath()
	if err != nil {
		return "", err
	}
	if err := writeFile(path, SystemdUnit(s)); err != nil {
		return "", err
	}
	for _, args := range [][]string{
		{"--user", "daemon-reload"},
		{"--user", "enable", Unit},
		{"--user", "restart", Unit},
	} {
		if err := run("systemctl", args...); err != nil {
			return "", err
		}
	}
	return path, nil
}

// Uninstall stops and disables the unit and removes it.
func Uninstall() (string, error) {
	path, err := unitPath()
	if err != nil {
		return "", err
	}
	_ = run("systemctl", "--user", "disable", "--now", Unit)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return "", err
	}
	_ = run("systemctl", "--user", "daemon-reload")
	return path, nil
}
