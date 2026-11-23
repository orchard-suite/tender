package service

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func plistPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "LaunchAgents", Label+".plist"), nil
}

func system() launchd {
	return launchd{run: func(args ...string) error { return run("launchctl", args...) }, sleep: time.Sleep}
}

func domain() string { return fmt.Sprintf("gui/%d", os.Getuid()) }

// Install writes the LaunchAgent and leaves it loaded on this build, as
// often as it is run.
func Install(s Spec) (string, error) {
	path, err := plistPath()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(s.LogDir, 0o700); err != nil {
		return "", err
	}
	if err := system().install(domain(), Label, path, []byte(LaunchAgent(s))); err != nil {
		return "", err
	}
	return path, nil
}

// Uninstall stops the LaunchAgent and removes it.
func Uninstall() (string, error) {
	path, err := plistPath()
	if err != nil {
		return "", err
	}
	return path, system().uninstall(domain(), Label, path)
}
