// Package service installs Tender as a per-user service that runs
// `tender run` in the person's session: a LaunchAgent on macOS, a systemd
// user unit on Linux, a scheduled task at logon on Windows.
package service

import (
	"fmt"
	"html"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Label is the LaunchAgent's label and the systemd unit's and scheduled
// task's name.
const (
	Label = "io.github.orchard-suite.tender"
	Unit  = "tender.service"
	Task  = "Tender"
)

// Spec says what the service runs.
type Spec struct {
	Exe    string // the absolute path of the tender program
	LogDir string // where launchd sends what the program writes to stderr
}

// LaunchAgent is the macOS plist.
func LaunchAgent(s Spec) string {
	esc := html.EscapeString
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>run</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<dict>
		<key>SuccessfulExit</key>
		<false/>
	</dict>
	<key>ThrottleInterval</key>
	<integer>60</integer>
	<key>ProcessType</key>
	<string>Background</string>
	<key>StandardErrorPath</key>
	<string>%s</string>
</dict>
</plist>
`, Label, esc(s.Exe), esc(filepath.Join(s.LogDir, "stderr.log")))
}

// SystemdUnit is the Linux user unit.
func SystemdUnit(s Spec) string {
	return fmt.Sprintf(`[Unit]
Description=Tender, the device agent
After=network-online.target

[Service]
ExecStart=%s run
Restart=on-failure
RestartSec=60

[Install]
WantedBy=default.target
`, systemdQuote(s.Exe))
}

func systemdQuote(p string) string {
	if !strings.ContainsAny(p, " \t\"'\\") {
		return p
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(p) + `"`
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func writeFile(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o644)
}

// TaskXML is the Windows task: at the person's logon, as that person, with
// no time limit, on battery too, started again when it stops.
func TaskXML(s Spec, userID string) string {
	esc := html.EscapeString
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Tender, the device agent</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>%[1]s</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>%[1]s</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Hidden>true</Hidden>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>999</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>conhost.exe</Command>
      <Arguments>--headless "%[2]s" run</Arguments>
    </Exec>
  </Actions>
</Task>
`, esc(userID), esc(s.Exe))
}
