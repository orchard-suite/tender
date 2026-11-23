package config

import (
	"os"
	"path/filepath"
	"runtime"
)

// Paths are where Tender keeps its files for the person it runs as.
type Paths struct {
	Config string // the config file
	State  string // the state directory: state.json, enrollment.json, enrolled key files
	Logs   string // the log directory
}

// DefaultPaths are the operating system's own places for one user:
//
//	macOS:   ~/Library/Application Support/tender, ~/Library/Logs/tender
//	Linux:   $XDG_CONFIG_HOME/tender, $XDG_STATE_HOME/tender
//	Windows: %APPDATA%\tender, %LOCALAPPDATA%\tender
//
// TENDER_CONFIG names another config file.
func DefaultPaths() (Paths, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Paths{}, err
	}
	cfgDir, err := os.UserConfigDir()
	if err != nil {
		return Paths{}, err
	}
	p := Paths{Config: filepath.Join(cfgDir, "tender", FileName)}
	switch runtime.GOOS {
	case "darwin":
		p.State = filepath.Join(cfgDir, "tender")
		p.Logs = filepath.Join(home, "Library", "Logs", "tender")
	case "windows":
		local := os.Getenv("LOCALAPPDATA")
		if local == "" {
			local = filepath.Join(home, "AppData", "Local")
		}
		p.State = filepath.Join(local, "tender")
		p.Logs = filepath.Join(local, "tender", "logs")
	default:
		state := os.Getenv("XDG_STATE_HOME")
		if state == "" {
			state = filepath.Join(home, ".local", "state")
		}
		p.State = filepath.Join(state, "tender")
		p.Logs = filepath.Join(state, "tender", "logs")
	}
	if c := os.Getenv("TENDER_CONFIG"); c != "" {
		p.Config = c
	}
	return p, nil
}
