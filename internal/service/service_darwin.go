package service

import (
	"fmt"
	"os"
	"path/filepath"
)

func plistPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "LaunchAgents", Label+".plist"), nil
}

// Install writes the LaunchAgent and starts it, replacing one that runs.
func Install(s Spec) (string, error) {
	path, err := plistPath()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(s.LogDir, 0o700); err != nil {
		return "", err
	}
	if err := writeFile(path, LaunchAgent(s)); err != nil {
		return "", err
	}
	domain := fmt.Sprintf("gui/%d", os.Getuid())
	_ = run("launchctl", "bootout", domain+"/"+Label) // not loaded yet is fine
	if err := run("launchctl", "bootstrap", domain, path); err != nil {
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
	_ = run("launchctl", "bootout", fmt.Sprintf("gui/%d/%s", os.Getuid(), Label))
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return "", err
	}
	return path, nil
}
