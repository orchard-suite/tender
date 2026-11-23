package service

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"time"
)

// launchd is how the LaunchAgent is loaded: launchctl, and a clock to wait
// on it. Tests replace both.
type launchd struct {
	run   func(args ...string) error // launchctl with args
	sleep func(time.Duration)
}

// gone is how long to wait for launchd to let go of a job it was told to
// unload, and how often to look.
const (
	goneWait = 10 * time.Second
	goneStep = 100 * time.Millisecond
)

// loaded reports whether the job is loaded in the domain.
func (l launchd) loaded(target string) bool { return l.run("print", target) == nil }

// unload boots the job out and waits until launchd no longer has it:
// bootout returns before the job is gone, and a bootstrap that follows too
// soon fails with "Bootstrap failed: 5".
func (l launchd) unload(target string) error {
	if !l.loaded(target) {
		return nil
	}
	_ = l.run("bootout", target) // a job that left on its own is fine
	for waited := time.Duration(0); waited < goneWait; waited += goneStep {
		if !l.loaded(target) {
			return nil
		}
		l.sleep(goneStep)
	}
	return fmt.Errorf("launchd still has %s %v after bootout", target, goneWait)
}

// install leaves the job loaded on what plist says, whatever was there
// before: a loaded job with the same plist is restarted in place, so it
// runs the program now at its path; a changed plist, or a job not loaded,
// is unloaded and bootstrapped afresh.
func (l launchd) install(domain, label, path string, plist []byte) error {
	target := domain + "/" + label
	old, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if bytes.Equal(old, plist) && l.loaded(target) {
		return l.run("kickstart", "-k", target)
	}
	if err := l.unload(target); err != nil {
		return err
	}
	if err := writeFile(path, string(plist)); err != nil {
		return err
	}
	return l.run("bootstrap", domain, path)
}

// uninstall unloads the job and removes its plist.
func (l launchd) uninstall(domain, label, path string) error {
	if err := l.unload(domain + "/" + label); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
