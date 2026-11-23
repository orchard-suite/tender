package agent_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/orchard-suite/tender/internal/agent"
	"github.com/orchard-suite/tender/internal/assertion"
	"github.com/orchard-suite/tender/internal/config"
	"github.com/orchard-suite/tender/internal/state"
	"github.com/orchard-suite/tender/internal/testpki"
)

// member is a fake member: each ask and post takes the next scripted
// answer, and repeats the last one when the script runs out.
type member struct {
	mu    sync.Mutex
	asks  []reply
	posts []reply
	got   []agent.Envelope
	nAsk  int
	auth  []string
}

type reply struct {
	status int
	body   string
}

func (m *member) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.auth = append(m.auth, r.Header.Get("Authorization"))
	var script *[]reply
	switch r.Method {
	case http.MethodGet:
		m.nAsk++
		script = &m.asks
	case http.MethodPost:
		b, _ := io.ReadAll(r.Body)
		var env agent.Envelope
		_ = json.Unmarshal(b, &env)
		m.got = append(m.got, env)
		script = &m.posts
	}
	rep := (*script)[0]
	if len(*script) > 1 {
		*script = (*script)[1:]
	}
	w.WriteHeader(rep.status)
	io.WriteString(w, rep.body)
}

// fakeReader writes whatever its report func says.
type fakeReader struct {
	versions []int
	reads    int
	report   func(version, n int) any
	err      error
}

func (f *fakeReader) Name() string    { return "muster" }
func (f *fakeReader) Versions() []int { return f.versions }
func (f *fakeReader) Read(_ context.Context, v int, _ yaml.Node) (any, error) {
	f.reads++
	if f.err != nil {
		return nil, f.err
	}
	return f.report(v, f.reads), nil
}

func checkouts(n int) func(int, int) any {
	return func(_, _ int) any { return map[string]any{"checkouts": make([]int, n)} }
}

type rig struct {
	t      *testing.T
	m      *member
	r      *fakeReader
	a      *agent.Agent
	now    time.Time
	server *httptest.Server
}

func newRig(t *testing.T, m *member, r *fakeReader) *rig {
	t.Helper()
	srv := httptest.NewServer(m)
	t.Cleanup(srv.Close)
	pki := testpki.New(t)
	key := testpki.Key(t)
	leaf := pki.Device(t, key.Public(), "laptop-1", "user@example.com", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	cfg, err := config.Parse([]byte("readers:\n  muster:\n    address: " + srv.URL + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	g := &rig{t: t, m: m, r: r, now: time.Date(2026, 11, 23, 14, 0, 0, 0, time.UTC), server: srv}
	g.a = &agent.Agent{
		Endpoints: []agent.Endpoint{{Endpoint: cfg.Endpoints()[0], Reader: r}},
		Key: func(context.Context) (assertion.Key, error) {
			return assertion.Key{Signer: key, Chain: pki.Chain(leaf)}, nil
		},
		HTTP:   srv.Client(),
		State:  &state.State{},
		Now:    func() time.Time { return g.now },
		Jitter: func() float64 { return 0 },
	}
	return g
}

func (g *rig) tick() time.Time           { return g.a.Tick(context.Background()) }
func (g *rig) advance(d time.Duration)   { g.now = g.now.Add(d) }
func (g *rig) reader() *state.Reader     { return g.a.State.Reader("muster") }
func (g *rig) outcome() string           { return g.reader().Last.Outcome }
func (g *rig) posts() []agent.Envelope   { return g.m.got }
func ok(body string) reply               { return reply{200, body} }
func status(code int, body string) reply { return reply{code, body} }
func accept(v int, every string) reply {
	return ok(`{"accept":true,"version":` + itoa(v) + `,"every":"` + every + `"}`)
}
func itoa(v int) string { b, _ := json.Marshal(v); return string(b) }
func (g *rig) checkoutsIn(i int) int {
	var r struct{ Checkouts []int }
	_ = json.Unmarshal(g.posts()[i].Report, &r)
	return len(r.Checkouts)
}

func TestAcceptReadsAndPostsOnTheMembersSchedule(t *testing.T) {
	m := &member{asks: []reply{accept(1, "10m")}, posts: []reply{status(204, "")}}
	g := newRig(t, m, &fakeReader{versions: []int{1}, report: checkouts(3)})

	next := g.tick()
	if len(g.posts()) != 1 {
		t.Fatalf("posts = %d, want 1", len(g.posts()))
	}
	p := g.posts()[0]
	if p.Reader != "muster" || p.Version != 1 || !p.At.Equal(g.now) || g.checkoutsIn(0) != 3 {
		t.Errorf("envelope = %+v", p)
	}
	if g.outcome() != agent.Sent || g.reader().Last.Counts["checkouts"] != 3 {
		t.Errorf("last = %+v", g.reader().Last)
	}
	if want := g.now.Add(10 * time.Minute); !next.Equal(want) || !g.reader().NextDue.Equal(want) {
		t.Errorf("next = %v, want %v", next, want)
	}
	for _, a := range m.auth {
		if !strings.HasPrefix(a, "Device ") || strings.Count(a, ".") != 2 {
			t.Errorf("Authorization = %q", a)
		}
	}

	g.advance(5 * time.Minute)
	g.tick()
	if m.nAsk != 1 || len(g.posts()) != 1 {
		t.Errorf("sent before due: asks %d posts %d", m.nAsk, len(g.posts()))
	}
	g.advance(5 * time.Minute)
	g.tick()
	if m.nAsk != 2 || len(g.posts()) != 2 {
		t.Errorf("did not send when due: asks %d posts %d", m.nAsk, len(g.posts()))
	}
}

func TestDeclineStaysQuietUntilRetry(t *testing.T) {
	m := &member{asks: []reply{ok(`{"accept":false,"retry":"2h"}`), ok(`{"accept":false}`)}}
	r := &fakeReader{versions: []int{1}, report: checkouts(1)}
	g := newRig(t, m, r)

	next := g.tick()
	if r.reads != 0 || len(g.posts()) != 0 || g.outcome() != agent.Declined {
		t.Fatalf("a no still read or sent: reads %d posts %d", r.reads, len(g.posts()))
	}
	if !next.Equal(g.now.Add(2 * time.Hour)) {
		t.Errorf("next = %v, want retry 2h", next)
	}
	g.advance(2 * time.Hour)
	next = g.tick()
	if !next.Equal(g.now.Add(agent.DefaultRetry)) {
		t.Errorf("next = %v, want the default retry of 6h", next)
	}
}

func TestUnsupportedVersionStaysQuiet(t *testing.T) {
	m := &member{asks: []reply{accept(2, "15m")}}
	r := &fakeReader{versions: []int{1}, report: checkouts(1)}
	g := newRig(t, m, r)
	next := g.tick()
	if r.reads != 0 || len(g.posts()) != 0 || g.outcome() != agent.Unsupported {
		t.Fatalf("an unsupported version was read or sent: reads %d posts %d", r.reads, len(g.posts()))
	}
	if !next.Equal(g.now.Add(agent.DefaultRetry)) {
		t.Errorf("next = %v", next)
	}
}

func TestConflictAsksAgainAndSendsTheNewVersion(t *testing.T) {
	m := &member{
		asks:  []reply{accept(1, "15m"), accept(2, "15m")},
		posts: []reply{status(409, `{"version":2}`), status(204, "")},
	}
	g := newRig(t, m, &fakeReader{versions: []int{1, 2}, report: checkouts(1)})
	g.tick()
	if m.nAsk != 2 || len(g.posts()) != 2 {
		t.Fatalf("asks %d posts %d, want 2 and 2", m.nAsk, len(g.posts()))
	}
	if g.posts()[1].Version != 2 || g.outcome() != agent.Sent {
		t.Errorf("second post = v%d, outcome %s", g.posts()[1].Version, g.outcome())
	}
}

func TestConflictAsksAgainOnlyOnce(t *testing.T) {
	m := &member{asks: []reply{accept(1, "15m")}, posts: []reply{status(409, `{"version":1}`)}}
	g := newRig(t, m, &fakeReader{versions: []int{1}, report: checkouts(1)})
	g.tick()
	if m.nAsk != 2 || len(g.posts()) != 2 {
		t.Fatalf("asks %d posts %d: a member that always says 409 must not loop", m.nAsk, len(g.posts()))
	}
	if g.a.Held("muster") {
		t.Error("a refused report is held")
	}
}

func TestServerErrorHoldsAndRetriesWithBackoff(t *testing.T) {
	m := &member{
		asks:  []reply{accept(1, "1h")},
		posts: []reply{status(503, "down"), status(502, ""), status(204, "")},
	}
	r := &fakeReader{versions: []int{1}, report: checkouts(2)}
	g := newRig(t, m, r)

	next := g.tick()
	if !g.a.Held("muster") || g.outcome() != agent.Held {
		t.Fatalf("a 503 did not hold the report: %+v", g.reader().Last)
	}
	if want := g.now.Add(agent.BackoffBase); !next.Equal(want) {
		t.Errorf("first retry at %v, want %v", next, want)
	}
	g.advance(agent.BackoffBase)
	next = g.tick()
	if want := g.now.Add(2 * agent.BackoffBase); !next.Equal(want) {
		t.Errorf("second retry at %v, want %v (doubling)", next, want)
	}
	g.advance(2 * agent.BackoffBase)
	g.tick()
	if g.a.Held("muster") || g.outcome() != agent.Sent {
		t.Fatalf("the retry did not send: %+v", g.reader().Last)
	}
	if r.reads != 1 || m.nAsk != 1 {
		t.Errorf("a retry read or asked again: reads %d asks %d", r.reads, m.nAsk)
	}
	if len(g.posts()) != 3 || string(g.posts()[0].Report) != string(g.posts()[2].Report) {
		t.Error("the retry did not send the same report")
	}
}

func TestNetworkFailureHolds(t *testing.T) {
	m := &member{asks: []reply{accept(1, "15m")}, posts: []reply{status(204, "")}}
	g := newRig(t, m, &fakeReader{versions: []int{1}, report: checkouts(1)})
	g.tick()
	g.server.Close() // the member goes away
	g.advance(15 * time.Minute)
	g.tick()
	if g.outcome() != agent.Failed || !strings.HasPrefix(g.reader().Last.Error, "ask:") {
		t.Fatalf("last = %+v", g.reader().Last)
	}
	if !g.reader().NextDue.Equal(g.now.Add(agent.BackoffBase)) {
		t.Errorf("a failed ask did not back off: next %v", g.reader().NextDue)
	}
}

func TestNewerReportReplacesAWaitingOne(t *testing.T) {
	m := &member{
		asks:  []reply{accept(1, "10m")},
		posts: []reply{status(500, ""), status(500, ""), status(500, ""), status(500, ""), status(500, ""), status(500, ""), status(204, "")},
	}
	r := &fakeReader{versions: []int{1}, report: func(_, n int) any { return map[string]any{"checkouts": make([]int, n)} }}
	g := newRig(t, m, r)

	g.tick() // read 1, held
	for g.now.Before(time.Date(2026, 11, 23, 14, 10, 0, 0, time.UTC)) {
		g.now = g.a.NextWake()
		g.tick()
	}
	// Until 14:10 every retry sends report 1. At 14:10 the reader is due
	// again: it reads report 2, which replaces 1.
	if r.reads != 2 || !g.a.Held("muster") {
		t.Fatalf("reads = %d held = %v, want 2 and a held report", r.reads, g.a.Held("muster"))
	}
	last := len(g.posts()) - 1
	for i := range last {
		if g.checkoutsIn(i) != 1 {
			t.Fatalf("retry %d sent report %d, want 1", i, g.checkoutsIn(i))
		}
	}
	if g.checkoutsIn(last) != 2 {
		t.Errorf("the post at the next due time sent report %d, want the newer one", g.checkoutsIn(last))
	}
	for g.a.Held("muster") {
		g.now = g.a.NextWake()
		g.tick()
	}
	if g.outcome() != agent.Sent || g.checkoutsIn(len(g.posts())-1) != 2 {
		t.Errorf("the newer report was not the one sent: %+v", g.reader().Last)
	}
}

func TestOverLongStringIsRefusedAndNotSent(t *testing.T) {
	m := &member{asks: []reply{accept(1, "15m")}, posts: []reply{status(204, "")}}
	g := newRig(t, m, &fakeReader{versions: []int{1}, report: func(int, int) any {
		return map[string]any{"checkouts": []any{map[string]any{"folder": strings.Repeat("x", 513)}}}
	}})
	g.tick()
	if len(g.posts()) != 0 || g.outcome() != agent.Refused {
		t.Fatalf("an over-long string was sent: posts %d, last %+v", len(g.posts()), g.reader().Last)
	}
	if strings.Contains(g.reader().Last.Error, "xxx") {
		t.Error("the result repeats the string")
	}
	if !g.reader().NextDue.Equal(g.now.Add(15 * time.Minute)) {
		t.Errorf("a refused report changed the schedule: %v", g.reader().NextDue)
	}
}

func TestClientErrorDropsTheReport(t *testing.T) {
	m := &member{asks: []reply{accept(1, "15m")}, posts: []reply{status(400, "bad report")}}
	g := newRig(t, m, &fakeReader{versions: []int{1}, report: checkouts(1)})
	g.tick()
	if g.a.Held("muster") || g.outcome() != agent.Failed || g.reader().Last.Status != 400 {
		t.Errorf("last = %+v held %v", g.reader().Last, g.a.Held("muster"))
	}
}

func TestReadFailureIsRecorded(t *testing.T) {
	m := &member{asks: []reply{accept(1, "15m")}}
	g := newRig(t, m, &fakeReader{versions: []int{1}, err: errors.New("git missing")})
	g.tick()
	if g.outcome() != agent.Failed || !strings.Contains(g.reader().Last.Error, "git missing") || len(g.posts()) != 0 {
		t.Errorf("last = %+v", g.reader().Last)
	}
}

func TestDeniedAskBacksOff(t *testing.T) {
	m := &member{asks: []reply{status(401, "certificate revoked")}}
	g := newRig(t, m, &fakeReader{versions: []int{1}, report: checkouts(1)})
	g.tick()
	l := g.reader().Last
	if l.Outcome != agent.Failed || l.Status != 401 || !strings.Contains(l.Error, "certificate revoked") {
		t.Errorf("last = %+v", l)
	}
	g.advance(agent.BackoffBase)
	g.tick()
	g.advance(2 * agent.BackoffBase)
	g.tick()
	if !g.reader().NextDue.Equal(g.now.Add(4 * agent.BackoffBase)) {
		t.Errorf("failures in a row did not double the wait: next %v", g.reader().NextDue)
	}
}

func TestBackoffIsCapped(t *testing.T) {
	m := &member{asks: []reply{status(503, "")}}
	g := newRig(t, m, &fakeReader{versions: []int{1}, report: checkouts(1)})
	for range 20 {
		g.now = g.a.NextWake()
		g.tick()
	}
	if d := g.reader().NextDue.Sub(g.now); d != agent.BackoffMax {
		t.Errorf("wait = %v, want the cap %v", d, agent.BackoffMax)
	}
}

func TestOnceRunsEveryReaderNow(t *testing.T) {
	m := &member{asks: []reply{accept(1, "15m")}, posts: []reply{status(204, "")}}
	g := newRig(t, m, &fakeReader{versions: []int{1}, report: checkouts(4)})
	g.tick()
	res := g.a.Once(context.Background()) // not due, but once sends anyway
	if len(g.posts()) != 2 || res["muster"].Outcome != agent.Sent || res["muster"].Counts["checkouts"] != 4 {
		t.Errorf("once: posts %d, result %+v", len(g.posts()), res)
	}
}
