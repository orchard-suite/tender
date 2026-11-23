package service

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeLaunchd is launchd as it behaves: bootout returns while the job is
// still going away, and a bootstrap of a job still loaded fails with 5.
type fakeLaunchd struct {
	loaded    bool
	lingering int // prints that still find the job after a bootout
	forever   bool
	calls     []string
	slept     time.Duration
}

func (f *fakeLaunchd) launchd() launchd {
	return launchd{
		run: func(args ...string) error {
			f.calls = append(f.calls, strings.Join(args, " "))
			switch args[0] {
			case "print":
				if !f.loaded {
					return errors.New("could not find service")
				}
				if f.lingering > 0 && !f.forever {
					f.lingering--
					if f.lingering == 0 {
						f.loaded = false
					}
				}
				return nil
			case "bootout":
				if !f.loaded {
					return errors.New("no such process")
				}
				f.lingering = 3
			case "bootstrap":
				if f.loaded {
					return errors.New("Bootstrap failed: 5: Input/output error")
				}
				f.loaded = true
			case "kickstart":
				if !f.loaded {
					return errors.New("could not find service")
				}
			}
			return nil
		},
		sleep: func(d time.Duration) { f.slept += d },
	}
}

func (f *fakeLaunchd) did(verb string) bool {
	for _, c := range f.calls {
		if strings.HasPrefix(c, verb) {
			return true
		}
	}
	return false
}

const target = "gui/501/" + Label

func TestInstallFirstTimeBootstraps(t *testing.T) {
	path := filepath.Join(t.TempDir(), Label+".plist")
	f := &fakeLaunchd{}
	if err := f.launchd().install("gui/501", Label, path, []byte("v1")); err != nil {
		t.Fatal(err)
	}
	if !f.loaded || !f.did("bootstrap") || f.did("bootout") {
		t.Errorf("calls = %v", f.calls)
	}
}

func TestRerunWithTheSamePlistRestartsInPlace(t *testing.T) {
	path := filepath.Join(t.TempDir(), Label+".plist")
	f := &fakeLaunchd{}
	l := f.launchd()
	if err := l.install("gui/501", Label, path, []byte("v1")); err != nil {
		t.Fatal(err)
	}
	f.calls = nil
	if err := l.install("gui/501", Label, path, []byte("v1")); err != nil {
		t.Fatal(err)
	}
	if !f.loaded || !f.did("kickstart -k "+target) || f.did("bootout") || f.did("bootstrap") {
		t.Errorf("calls = %v", f.calls)
	}
}

func TestRerunWithANewPlistWaitsForTheOldJobToGo(t *testing.T) {
	path := filepath.Join(t.TempDir(), Label+".plist")
	f := &fakeLaunchd{}
	l := f.launchd()
	if err := l.install("gui/501", Label, path, []byte("v1")); err != nil {
		t.Fatal(err)
	}
	f.calls = nil
	if err := l.install("gui/501", Label, path, []byte("v2")); err != nil {
		t.Fatalf("%v; calls = %v", err, f.calls)
	}
	if !f.loaded || !f.did("bootout") || !f.did("bootstrap") || f.slept == 0 {
		t.Errorf("calls = %v, slept %v", f.calls, f.slept)
	}
	if b, _ := os.ReadFile(path); string(b) != "v2" {
		t.Errorf("plist = %q", b)
	}
}

func TestPlistThereButNotLoadedIsBootstrapped(t *testing.T) {
	path := filepath.Join(t.TempDir(), Label+".plist")
	if err := os.WriteFile(path, []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	f := &fakeLaunchd{}
	if err := f.launchd().install("gui/501", Label, path, []byte("v1")); err != nil {
		t.Fatal(err)
	}
	if !f.loaded || f.did("kickstart") {
		t.Errorf("an unloaded agent was not loaded: calls = %v", f.calls)
	}
}

func TestAJobThatNeverGoesIsAnErrorNotAHang(t *testing.T) {
	path := filepath.Join(t.TempDir(), Label+".plist")
	f := &fakeLaunchd{loaded: true, forever: true}
	err := f.launchd().install("gui/501", Label, path, []byte("v2"))
	if err == nil || f.slept < goneWait {
		t.Errorf("err = %v, slept %v", err, f.slept)
	}
	if f.did("bootstrap") {
		t.Error("bootstrapped over a job still loaded")
	}
}

func TestUninstallWaitsAndRemoves(t *testing.T) {
	path := filepath.Join(t.TempDir(), Label+".plist")
	f := &fakeLaunchd{}
	l := f.launchd()
	if err := l.install("gui/501", Label, path, []byte("v1")); err != nil {
		t.Fatal(err)
	}
	if err := l.uninstall("gui/501", Label, path); err != nil {
		t.Fatal(err)
	}
	if f.loaded {
		t.Error("still loaded")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("plist left behind")
	}
	if err := l.uninstall("gui/501", Label, path); err != nil {
		t.Errorf("a second uninstall failed: %v", err)
	}
}
