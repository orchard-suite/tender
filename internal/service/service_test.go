package service

import (
	"encoding/xml"
	"strings"
	"testing"
)

func TestDefinitionsRunTenderAsTheUser(t *testing.T) {
	s := Spec{Exe: "/Users/a user/.local/bin/tender", LogDir: "/tmp/logs"}

	plist := LaunchAgent(s)
	if err := xml.Unmarshal([]byte(plist), new(any)); err != nil {
		t.Errorf("the plist is not XML: %v", err)
	}
	for _, want := range []string{"<string>" + Label + "</string>", "<string>/Users/a user/.local/bin/tender</string>", "<string>run</string>", "<key>RunAtLoad</key>"} {
		if !strings.Contains(plist, want) {
			t.Errorf("plist lacks %s", want)
		}
	}

	if unit := SystemdUnit(s); !strings.Contains(unit, `ExecStart="/Users/a user/.local/bin/tender" run`) || !strings.Contains(unit, "WantedBy=default.target") {
		t.Errorf("unit = %s", unit)
	}

	task := TaskXML(Spec{Exe: `C:\Users\a&b\tender.exe`}, `ACME\user`)
	if err := xml.Unmarshal([]byte(strings.Replace(task, `encoding="UTF-16"`, "", 1)), new(any)); err != nil {
		t.Errorf("the task is not XML: %v", err)
	}
	for _, want := range []string{`--headless "C:\Users\a&amp;b\tender.exe" run`, "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>", `<UserId>ACME\user</UserId>`, "<LogonTrigger>"} {
		if !strings.Contains(task, want) {
			t.Errorf("task lacks %s", want)
		}
	}
}
