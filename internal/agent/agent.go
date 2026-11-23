// Package agent is Tender's loop: for each reader that has an address, ask
// the member, read, and post, on the member's schedule, holding a report
// that could not be sent and sending it again with backoff.
package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"time"

	"github.com/orchard-suite/tender/internal/assertion"
	"github.com/orchard-suite/tender/internal/config"
	"github.com/orchard-suite/tender/internal/reader"
	"github.com/orchard-suite/tender/internal/state"
)

const (
	// DefaultEvery is how often to send when a member that accepts names no
	// schedule.
	DefaultEvery = 15 * time.Minute
	// MinEvery is the shortest schedule Tender keeps, whatever a member asks.
	MinEvery = time.Minute
	// DefaultRetry is how long to stay quiet after a no, when the member
	// names no time.
	DefaultRetry = 6 * time.Hour
	// BackoffBase and BackoffMax bound the wait after a failure.
	BackoffBase = 30 * time.Second
	BackoffMax  = 30 * time.Minute

	maxResponse = 64 << 10
)

// Outcomes recorded in a reader's last result.
const (
	Sent        = "sent"        // the member took the report
	Declined    = "declined"    // the member said no to the ask
	Unsupported = "unsupported" // the member takes a version this reader cannot write
	Refused     = "refused"     // Tender refused the report: a string over the limit
	Held        = "held"        // the send failed and the report waits to go again
	Failed      = "failed"      // the ask, the read, or the send failed
	Reask       = "reask"       // the member wants another version
)

// Endpoint is a reader that is on, with the reader that serves it.
type Endpoint struct {
	config.Endpoint
	Reader reader.Reader
}

// Agent runs the readers. Set every field but the unexported ones.
type Agent struct {
	Endpoints []Endpoint
	Key       func(context.Context) (assertion.Key, error)
	HTTP      *http.Client
	State     *state.State
	Now       func() time.Time
	Jitter    func() float64 // in [0, 1); nil means random
	UserAgent string
	Log       *slog.Logger

	pending  map[string]*pending
	failures map[string]int
}

// pending is a report that waits to be sent again.
type pending struct {
	body     []byte
	version  int
	counts   map[string]int
	attempts int
	retryAt  time.Time
}

// Envelope is the body of a post.
type Envelope struct {
	Reader  string          `json:"reader"`
	Version int             `json:"version"`
	At      time.Time       `json:"at"`
	Report  json.RawMessage `json:"report"`
}

// Tick does everything due now and says when something is next due. A
// reader whose time has come asks, reads, and posts; a held report whose
// retry has come is posted again.
func (a *Agent) Tick(ctx context.Context) time.Time {
	a.init()
	now := a.Now()
	for _, e := range a.Endpoints {
		rs := a.State.Reader(e.Name)
		switch p := a.pending[e.Name]; {
		case !now.Before(rs.NextDue):
			a.cycle(ctx, e, rs)
		case p != nil && !now.Before(p.retryAt):
			a.post(ctx, e, rs, p)
		}
	}
	return a.NextWake()
}

// Once asks, reads, and posts for every reader now, whatever is due, and
// returns each reader's result.
func (a *Agent) Once(ctx context.Context) map[string]state.Result {
	a.init()
	out := map[string]state.Result{}
	for _, e := range a.Endpoints {
		rs := a.State.Reader(e.Name)
		a.cycle(ctx, e, rs)
		if rs.Last != nil {
			out[e.Name] = *rs.Last
		}
	}
	return out
}

// NextWake is the earliest time anything is due.
func (a *Agent) NextWake() time.Time {
	var next time.Time
	earlier := func(t time.Time) {
		if next.IsZero() || t.Before(next) {
			next = t
		}
	}
	for _, e := range a.Endpoints {
		earlier(a.State.Reader(e.Name).NextDue)
		if p := a.pending[e.Name]; p != nil {
			earlier(p.retryAt)
		}
	}
	return next
}

// Held reports whether a reader has a report waiting to go again.
func (a *Agent) Held(name string) bool { return a.pending[name] != nil }

func (a *Agent) init() {
	if a.pending == nil {
		a.pending = map[string]*pending{}
		a.failures = map[string]int{}
	}
	if a.Log == nil {
		a.Log = slog.New(slog.DiscardHandler)
	}
}

// cycle asks, reads, and posts once. A 409 asks again, once.
func (a *Agent) cycle(ctx context.Context, e Endpoint, rs *state.Reader) {
	start := a.Now()
	for range 2 {
		ans, status, err := a.ask(ctx, e)
		if err != nil {
			a.failures[e.Name]++
			rs.NextDue = start.Add(a.backoff(a.failures[e.Name]))
			a.record(e, rs, state.Result{At: start, Outcome: Failed, Status: status, Error: "ask: " + err.Error()})
			return
		}
		a.failures[e.Name] = 0
		rs.Answer, rs.AskedAt = &ans, start
		if !ans.Accept {
			delete(a.pending, e.Name)
			rs.NextDue = start.Add(duration(ans.Retry, DefaultRetry))
			a.record(e, rs, state.Result{At: start, Outcome: Declined})
			return
		}
		if !reader.Supports(e.Reader, ans.Version) {
			delete(a.pending, e.Name)
			rs.NextDue = start.Add(duration(ans.Retry, DefaultRetry))
			a.record(e, rs, state.Result{At: start, Outcome: Unsupported, Version: ans.Version})
			return
		}
		rs.NextDue = start.Add(max(duration(ans.Every, DefaultEvery), MinEvery))

		report, err := e.Reader.Read(ctx, ans.Version, e.Settings)
		if err != nil {
			a.record(e, rs, state.Result{At: start, Outcome: Failed, Version: ans.Version, Error: "read: " + err.Error()})
			return
		}
		raw, err := reader.Encode(report)
		if err != nil {
			a.record(e, rs, state.Result{At: start, Outcome: Refused, Version: ans.Version, Error: err.Error()})
			return
		}
		body, err := json.Marshal(Envelope{Reader: e.Name, Version: ans.Version, At: a.Now().UTC().Truncate(time.Second), Report: raw})
		if err != nil {
			a.record(e, rs, state.Result{At: start, Outcome: Failed, Error: err.Error()})
			return
		}
		// A newer report replaces one that waits.
		p := &pending{body: body, version: ans.Version, counts: reader.Counts(raw)}
		a.pending[e.Name] = p
		if !a.post(ctx, e, rs, p) {
			return
		}
	}
}

// post sends a report. It reports true when the member wants another
// version, so the caller asks again.
func (a *Agent) post(ctx context.Context, e Endpoint, rs *state.Reader, p *pending) bool {
	status, resp, err := a.send(ctx, http.MethodPost, e.URL, p.body)
	now := a.Now()
	res := state.Result{At: now, Status: status, Version: p.version, Bytes: len(p.body), Counts: p.counts}
	switch {
	case err == nil && status/100 == 2:
		delete(a.pending, e.Name)
		res.Outcome, rs.LastOK = Sent, now
	case status == http.StatusConflict:
		delete(a.pending, e.Name)
		var want struct {
			Version int `json:"version"`
		}
		_ = json.Unmarshal(resp, &want)
		res.Outcome, res.Error = Reask, fmt.Sprintf("the member wants version %d", want.Version)
		a.record(e, rs, res)
		return true
	case err != nil || status >= 500:
		p.attempts++
		p.retryAt = now.Add(a.backoff(p.attempts))
		res.Outcome = Held
		res.Error = errorText(err, status, resp)
	default:
		delete(a.pending, e.Name)
		res.Outcome, res.Error = Failed, errorText(err, status, resp)
	}
	a.record(e, rs, res)
	return false
}

// ask is the GET that says whether the member takes this reader, and how.
func (a *Agent) ask(ctx context.Context, e Endpoint) (state.Answer, int, error) {
	status, body, err := a.send(ctx, http.MethodGet, e.URL, nil)
	if err != nil {
		return state.Answer{}, status, err
	}
	if status != http.StatusOK {
		return state.Answer{}, status, errors.New(errorText(nil, status, body))
	}
	var ans state.Answer
	if err := json.Unmarshal(body, &ans); err != nil {
		return state.Answer{}, status, fmt.Errorf("the answer is not JSON: %w", err)
	}
	return ans, status, nil
}

// send makes one signed request.
func (a *Agent) send(ctx context.Context, method string, u *url.URL, body []byte) (int, []byte, error) {
	key, err := a.Key(ctx)
	if err != nil {
		return 0, nil, fmt.Errorf("identity: %w", err)
	}
	tok, err := assertion.Sign(key, method, u, body, a.Now())
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	if body == nil {
		req.Body, req.ContentLength = http.NoBody, 0
	} else {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", assertion.Scheme+" "+tok)
	req.Header.Set("Accept", "application/json")
	if a.UserAgent != "" {
		req.Header.Set("User-Agent", a.UserAgent)
	}
	resp, err := a.HTTP.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	return resp.StatusCode, b, err
}

func (a *Agent) record(e Endpoint, rs *state.Reader, res state.Result) {
	rs.Last = &res
	attrs := []any{"reader", e.Name, "outcome", res.Outcome, "next_due", rs.NextDue.UTC()}
	if res.Status != 0 {
		attrs = append(attrs, "status", res.Status)
	}
	if res.Version != 0 {
		attrs = append(attrs, "version", res.Version)
	}
	if res.Bytes != 0 {
		attrs = append(attrs, "bytes", res.Bytes)
	}
	if len(res.Counts) > 0 {
		attrs = append(attrs, "counts", res.Counts)
	}
	if p := a.pending[e.Name]; p != nil && res.Outcome == Held {
		attrs = append(attrs, "attempts", p.attempts, "retry_at", p.retryAt.UTC())
	}
	level := slog.LevelInfo
	switch res.Outcome {
	case Failed, Refused, Held:
		level = slog.LevelWarn
		attrs = append(attrs, "error", res.Error)
	}
	a.Log.Log(context.Background(), level, "reader "+res.Outcome, attrs...)
}

// backoff is how long to wait after the nth failure in a row: doubling from
// BackoffBase to BackoffMax, plus up to a quarter more so a fleet spreads
// out after an outage.
func (a *Agent) backoff(n int) time.Duration {
	d := BackoffBase
	for i := 1; i < n && d < BackoffMax; i++ {
		d *= 2
	}
	d = min(d, BackoffMax)
	j := rand.Float64
	if a.Jitter != nil {
		j = a.Jitter
	}
	return d + time.Duration(float64(d)/4*j())
}

func duration(s string, def time.Duration) time.Duration {
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return d
	}
	return def
}

func errorText(err error, status int, body []byte) string {
	if err != nil {
		return err.Error()
	}
	msg := http.StatusText(status)
	if s := bytes.TrimSpace(body); len(s) > 0 {
		if len(s) > 200 {
			s = s[:200]
		}
		msg += ": " + string(s)
	}
	return fmt.Sprintf("%d %s", status, msg)
}
