package runner_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"sigelith.org/cosigner/internal/logtree"
	"sigelith.org/cosigner/internal/runner"
	"sigelith.org/cosigner/internal/signer"
	"sigelith.org/cosigner/internal/store"
)

type logEntry struct {
	Seq       int64  `json:"seq"`
	Digest    string `json:"digest"`
	UTC       string `json:"utc"`
	ChainHash string `json:"chain_hash"`
	PrevChain string `json:"prev_chain"`
	Week      string `json:"week"`
}

// fakeLog to dziennik Sigelith w miniaturze: /api/proof/entries i /api/cosign.
type fakeLog struct {
	mu         sync.Mutex
	entries    []logEntry
	pageSize   int
	cosignCode int
	received   []string
}

func (f *fakeLog) add(t *testing.T, seq int64, digest, utc string) {
	t.Helper()
	ts, err := logtree.ParseCanonical(utc)
	if err != nil {
		t.Fatal(err)
	}
	prev := logtree.Genesis
	if n := len(f.entries); n > 0 {
		prev = f.entries[n-1].ChainHash
	}
	f.entries = append(f.entries, logEntry{seq, digest, utc, logtree.ChainHash(prev, digest, ts), prev, "2026-W40"})
}

func (f *fakeLog) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/proof/entries":
		from, _ := strconv.ParseInt(r.URL.Query().Get("from"), 10, 64)
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if f.pageSize > 0 && f.pageSize < limit {
			limit = f.pageSize
		}
		page := []logEntry{}
		var next any
		for _, e := range f.entries {
			if e.Seq < from {
				continue
			}
			if len(page) == limit {
				next = page[len(page)-1].Seq + 1
				break
			}
			page = append(page, e)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"entries": page, "next": next})
	case r.Method == http.MethodPost && r.URL.Path == "/api/cosign":
		body, _ := io.ReadAll(r.Body)
		code := f.cosignCode
		if code == 0 {
			code = http.StatusCreated
		}
		if code == http.StatusCreated {
			f.received = append(f.received, string(body))
		}
		w.WriteHeader(code)
		_, _ = w.Write([]byte(`{"detail":"test"}`))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

type harness struct {
	t      *testing.T
	log    *fakeLog
	srv    *httptest.Server
	r      *runner.Runner
	clock  time.Time
	signer *signer.File
}

func newHarness(t *testing.T) *harness {
	h := &harness{t: t, log: &fakeLog{}}
	h.srv = httptest.NewServer(h.log)
	t.Cleanup(h.srv.Close)
	dir := t.TempDir()
	h.signer = &signer.File{Path: filepath.Join(dir, "cosigner.key")}
	h.clock = time.Date(2026, 9, 28, 12, 5, 0, 0, time.UTC)
	h.r = &runner.Runner{
		Cfg:    runner.Config{LogURL: h.srv.URL, Name: "test-guard"},
		Store:  store.File{Path: filepath.Join(dir, "state.json")},
		Signer: h.signer,
		Now:    func() time.Time { return h.clock },
	}
	// Wektory z LOG.md, sekcja 10.
	h.log.add(t, 1, "d426a3a1df05344e837b26a904177329f16f15aa4f9f934aa53d5c091a45cf0a", "2026-09-28T00:00:00.000000Z")
	h.log.add(t, 2, "cd53115f14511240719ef645d2cc250c84b6c8e3a3187951c9cba54fb3850436", "2026-09-28T09:06:03.926713Z")
	h.log.add(t, 4, "3e6f0b0a97d1c5062629486dc6c632db1a5339c3d2bc49d3634d4bfa97b6a126", "2026-09-28T12:00:00.500000Z")
	return h
}

func (h *harness) run() runner.Result {
	h.t.Helper()
	res, err := h.r.RunOnce(context.Background())
	if err != nil {
		h.t.Fatalf("przebieg: %v", err)
	}
	return res
}

func (h *harness) runAlarm(fragment string) {
	h.t.Helper()
	res, err := h.r.RunOnce(context.Background())
	if err == nil || !strings.Contains(res.Alarm, fragment) {
		h.t.Fatalf("oczekiwany alarm z %q, jest: %+v %v", fragment, res, err)
	}
	if _, err := h.r.RunOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "wstrzymany") {
		h.t.Fatalf("po alarmie straznik dziala dalej: %v", err)
	}
}

func lastCosignature(t *testing.T, f *fakeLog) map[string]any {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.received) == 0 {
		t.Fatal("dziennik nie dostal podpisu")
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(f.received[len(f.received)-1]), &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestFirstRunSignsTheWholeLog(t *testing.T) {
	h := newHarness(t)
	res := h.run()
	if !res.Signed || res.Size != 3 || res.Delivered != 1 || res.Pending != 0 {
		t.Fatalf("wynik: %+v", res)
	}
	doc := lastCosignature(t, h.log)
	if doc["root"] != "bda0c891af7812124648447e1402ec9a9af54ced96e5600ac017f01512d5428d" ||
		doc["since"] != nil || doc["last_seq"] != float64(4) || doc["log"] != strings.TrimPrefix(h.srv.URL, "http://") ||
		doc["time"] != "2026-09-28T12:05:00.000000Z" || doc["cosigner"] != "test-guard" {
		t.Fatalf("podpis: %v", doc)
	}
	// Podpis sprawdzalny kluczem z dokumentu, wiadomosc odtwarzalna z tresci.
	sig, _ := base64.StdEncoding.DecodeString(doc["sig"].(string))
	delete(doc, "sig")
	body, _ := json.Marshal(doc) // klucze mapy Go sa sortowane
	body = bytes.ReplaceAll(body, []byte(`&`), []byte("&"))
	pub, _ := base64.StdEncoding.DecodeString(doc["key"].(string))
	if !ed25519.Verify(pub, append([]byte("sigelith-cosign-v1|"), body...), sig) {
		t.Fatal("podpis nie przechodzi weryfikacji z odtworzonej tresci")
	}
	if res := h.run(); res.Signed {
		t.Fatal("podpis bez nowych wpisow przed uplywem godziny")
	}
}

func TestNewEntryGetsAWindowAndHeartbeat(t *testing.T) {
	h := newHarness(t)
	h.run()
	h.log.add(t, 5, strings.Repeat("ab", 32), "2026-09-28T12:05:30.000000Z")
	h.clock = h.clock.Add(time.Minute)
	res := h.run()
	doc := lastCosignature(t, h.log)
	since, _ := doc["since"].(map[string]any)
	if !res.Signed || res.NewEntries != 1 || doc["size"] != float64(4) || since == nil ||
		since["size"] != float64(3) || since["time"] != "2026-09-28T12:05:00.000000Z" {
		t.Fatalf("okno nowego wpisu: %+v %v", res, doc)
	}
	h.clock = h.clock.Add(61 * time.Minute)
	if res := h.run(); !res.Signed {
		t.Fatal("brak podpisu po godzinie bez wpisow")
	}
	doc = lastCosignature(t, h.log)
	since, _ = doc["since"].(map[string]any)
	if doc["size"] != float64(4) || since["size"] != float64(4) {
		t.Fatalf("podpis „jestem\": %v", doc)
	}
}

func TestBackdatedEntryStopsTheGuard(t *testing.T) {
	h := newHarness(t)
	h.run()
	h.clock = h.clock.Add(time.Minute)
	h.log.add(t, 5, strings.Repeat("cd", 32), "2026-09-28T12:04:00.000000Z") // 60 s przed obserwacja
	h.runAlarm("datowany wstecz")
}

func TestFutureEntryStopsTheGuard(t *testing.T) {
	h := newHarness(t)
	h.log.add(t, 5, strings.Repeat("cd", 32), "2026-09-28T12:06:00.000000Z") // 60 s po zegarze straznika
	h.runAlarm("pozniejszy niz zegar")
}

func TestBrokenChainStopsTheGuard(t *testing.T) {
	h := newHarness(t)
	h.log.entries[1].PrevChain = strings.Repeat("0", 63) + "1"
	h.runAlarm("lancuch przerwany")
}

func TestUndeliveredCosignatureWaitsAndConflictStops(t *testing.T) {
	h := newHarness(t)
	h.log.cosignCode = http.StatusServiceUnavailable
	if res := h.run(); res.Pending != 1 || res.Delivered != 0 {
		t.Fatalf("podpis powinien czekac: %+v", res)
	}
	h.log.cosignCode = 0
	h.log.add(t, 5, strings.Repeat("ab", 32), "2026-09-28T12:05:30.000000Z")
	h.clock = h.clock.Add(time.Minute)
	if res := h.run(); res.Delivered != 2 || res.Pending != 0 {
		t.Fatalf("zalegly podpis nie doszedl: %+v", res)
	}
	h.log.cosignCode = http.StatusConflict
	h.log.add(t, 6, strings.Repeat("ef", 32), "2026-09-28T12:06:30.000000Z")
	h.clock = h.clock.Add(time.Minute)
	h.runAlarm("nie zgadza sie")
}

func TestKeyChangeStopsTheGuard(t *testing.T) {
	h := newHarness(t)
	h.run()
	h.r.Signer = &signer.File{Path: filepath.Join(h.t.TempDir(), "other.key")}
	h.runAlarm("zmienil sie klucz")
}

func TestPartialFetchDoesNotMoveTheLowerBound(t *testing.T) {
	h := newHarness(t)
	h.log.pageSize = 1
	h.r.Cfg.MaxPages = 2
	if res := h.run(); res.Size != 2 || !res.Signed {
		t.Fatalf("pierwsza czesc: %+v", res)
	}
	// Wpis 4 (12:00:00.5) jest starszy niz obserwacja 12:05 minus 30 s, ale nie
	// byl jeszcze pobrany — nie wolno go uznac za datowany wstecz.
	h.clock = h.clock.Add(time.Minute)
	if res := h.run(); res.Size != 3 {
		t.Fatalf("doczytanie reszty: %+v", res)
	}
}
