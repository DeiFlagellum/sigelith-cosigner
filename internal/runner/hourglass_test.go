package runner_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"sigelith.org/cosigner/internal/cosign"
	"sigelith.org/cosigner/internal/hourglass"
	"sigelith.org/cosigner/internal/runner"
)

// fakeClock to zegar Klepsydry opublikowany w dzienniku: ciag v1 z wektorow
// sigelith-hourglass (genesis + 2 odcinki podpisane kluczem testowym).
type fakeClock struct {
	name, operator string
	genesis        []byte
	genesisRoot    string
	records        [][]byte // dokladne bajty opublikowanych rekordow, [0] = odcinek 1
	roots          []string
	proofs         [][]byte
	latest         int    // ile odcinkow widac
	latestRoot     string // podmiana korzenia ostatniego odcinka na liscie (rozwidlenie)
}

type fakeHG struct {
	log         *fakeLog
	mu          sync.Mutex
	clocks      []*fakeClock
	confirmCode int
	confirms    []string
}

func (f *fakeHG) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Path, "/api/hourglass/") {
		f.log.ServeHTTP(w, r)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/api/hourglass/")
	if r.Method == http.MethodPost && path == "confirm" {
		body, _ := io.ReadAll(r.Body)
		code := f.confirmCode
		if code == 0 {
			code = http.StatusCreated
		}
		if code == http.StatusCreated {
			f.confirms = append(f.confirms, string(body))
		}
		w.WriteHeader(code)
		_, _ = w.Write([]byte(`{"error":"test"}`))
		return
	}
	if path == "clocks" {
		list := []map[string]any{}
		for _, c := range f.clocks {
			root := c.genesisRoot
			if c.latest > 0 {
				root = c.roots[c.latest-1]
			}
			if c.latestRoot != "" {
				root = c.latestRoot
			}
			list = append(list, map[string]any{"clock": c.name, "operator": c.operator,
				"genesis_root": c.genesisRoot, "latest_segment": c.latest, "latest_root": root})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"clocks": list})
		return
	}
	parts := strings.Split(path, "/")
	for _, c := range f.clocks {
		if parts[0] != c.name {
			continue
		}
		switch {
		case len(parts) == 2 && parts[1] == "genesis":
			_, _ = w.Write(c.genesis)
			return
		case len(parts) >= 3 && parts[1] == "segments":
			j, err := strconv.Atoi(parts[2])
			if err != nil || j < 1 || j > c.latest {
				break
			}
			if len(parts) == 3 {
				_, _ = w.Write(c.records[j-1])
				return
			}
			if len(parts) == 4 && parts[3] == "proof" {
				_, _ = w.Write(c.proofs[j-1])
				return
			}
		}
	}
	w.WriteHeader(http.StatusNotFound)
}

type hgVectors struct {
	V1 struct {
		Chain struct {
			Genesis     json.RawMessage                 `json:"genesis"`
			GenesisRoot string                          `json:"genesis_root"`
			TestKey     struct{ Secret, Public string } `json:"test_key"`
			Segments    []json.RawMessage               `json:"segments"`
			Proofs      []string                        `json:"proofs"`
		} `json:"chain"`
	} `json:"v1"`
}

func canonical(t *testing.T, raw []byte) ([]byte, map[string]any) {
	t.Helper()
	obj, err := hourglass.DecodeObject(raw)
	if err != nil {
		t.Fatal(err)
	}
	data, err := hourglass.Canonical(obj)
	if err != nil {
		t.Fatal(err)
	}
	return data, obj
}

func exampleClock(t *testing.T) (*fakeClock, string) {
	t.Helper()
	data, err := os.ReadFile("../hourglass/testdata/hourglass-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v hgVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	ch := v.V1.Chain
	g, gobj := canonical(t, ch.Genesis)
	c := &fakeClock{name: "example", operator: gobj["operator"].(string), genesis: g, genesisRoot: ch.GenesisRoot}
	for i, raw := range ch.Segments {
		rec, obj := canonical(t, raw)
		proof, _ := hex.DecodeString(ch.Proofs[i])
		c.records = append(c.records, rec)
		c.roots = append(c.roots, obj["root"].(string))
		c.proofs = append(c.proofs, proof)
	}
	c.latest = len(c.records)
	return c, ch.TestKey.Public
}

func newHGHarness(t *testing.T) (*harness, *fakeHG, *fakeClock, string) {
	h := newHarness(t)
	hg := &fakeHG{log: h.log}
	h.srv.Config.Handler = hg
	h.clock = time.Date(2026, 11, 23, 1, 0, 0, 0, time.UTC)
	c, key := exampleClock(t)
	hg.clocks = []*fakeClock{c}
	return h, hg, c, key
}

func (f *fakeHG) confirmations(t *testing.T) []map[string]any {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []map[string]any
	for _, raw := range f.confirms {
		var doc map[string]any
		if err := json.Unmarshal([]byte(raw), &doc); err != nil {
			t.Fatal(err)
		}
		out = append(out, doc)
	}
	return out
}

func TestHourglassConfirmsEverySegment(t *testing.T) {
	h, hg, c, key := newHGHarness(t)
	res := h.run()
	if !res.Signed || res.HGConfirmed != 2 || res.HGDelivered != 2 || res.HGPending != 0 || len(res.HGAlarms) != 0 {
		t.Fatalf("wynik: %+v", res)
	}
	docs := hg.confirmations(t)
	pub, _ := h.signer.PublicKey(nil)
	for i, doc := range docs {
		sum := sha256.Sum256(c.records[i])
		conf := cosign.Confirmation{
			Log: strings.TrimPrefix(h.srv.URL, "http://"), Cosigner: "test-guard",
			Key: base64.StdEncoding.EncodeToString(pub), Clock: "example", Genesis: c.genesisRoot,
			J: int64(i + 1), Root: c.roots[i], Record: hex.EncodeToString(sum[:]), Time: "2026-11-23T01:00:00.000000Z",
		}
		sig, _ := base64.StdEncoding.DecodeString(doc["sig"].(string))
		if err := conf.Verify(sig); err != nil {
			t.Fatalf("potwierdzenie %d: %v (%v)", i+1, err, doc)
		}
		want, _ := conf.Document(sig)
		if hg.confirms[i] != string(want) {
			t.Fatalf("dokument %d:\n%s\n%s", i+1, hg.confirms[i], want)
		}
	}
	st, _, _ := h.r.Store.Load(nil)
	hc := st.Hourglass["example"]
	if hc == nil || hc.J != 2 || hc.Root != c.roots[1] || hc.Key != key || hc.Genesis != c.genesisRoot {
		t.Fatalf("stan zegara: %+v", hc)
	}
	if res := h.run(); res.HGConfirmed != 0 || res.HGDelivered != 0 {
		t.Fatalf("drugi przebieg potwierdzil jeszcze raz: %+v", res)
	}
}

func TestHourglassOneSegmentAtATime(t *testing.T) {
	h, hg, c, _ := newHGHarness(t)
	c.latest = 1
	if res := h.run(); res.HGConfirmed != 1 {
		t.Fatalf("wynik: %+v", res)
	}
	hg.mu.Lock()
	c.latest = 2
	hg.mu.Unlock()
	if res := h.run(); res.HGConfirmed != 1 || len(hg.confirmations(t)) != 2 {
		t.Fatalf("wynik: %+v", res)
	}
}

// Zly odcinek wstrzymuje TYLKO potwierdzenia tego zegara; podpisy dziennika ida dalej.
func TestHourglassBadProofAlarmsOnlyThatClock(t *testing.T) {
	h, hg, c, _ := newHGHarness(t)
	c.proofs[1] = append([]byte(nil), c.proofs[1]...)
	c.proofs[1][100] ^= 1
	res := h.run()
	if !res.Signed || res.HGConfirmed != 1 || len(res.HGAlarms) != 1 ||
		!strings.Contains(res.HGAlarms[0], "odcinek 2 NIE przechodzi sprawdzenia") {
		t.Fatalf("wynik: %+v", res)
	}
	h.log.add(t, 5, strings.Repeat("ab", 32), "2026-11-23T00:59:50.000000Z")
	h.clock = h.clock.Add(time.Minute)
	if res := h.run(); !res.Signed || res.HGConfirmed != 0 || len(res.HGAlarms) != 1 {
		t.Fatalf("po alarmie zegara dziennik nie jest podpisywany albo zegar dalej potwierdzany: %+v", res)
	}
	if len(hg.confirmations(t)) != 1 {
		t.Fatal("potwierdzony zly odcinek")
	}
}

func TestHourglassForkAndShorterChain(t *testing.T) {
	h, hg, c, _ := newHGHarness(t)
	h.run()
	hg.mu.Lock()
	c.latestRoot = strings.Repeat("0", 64)
	hg.mu.Unlock()
	if res := h.run(); len(res.HGAlarms) != 1 || !strings.Contains(res.HGAlarms[0], "rozwidlenie") {
		t.Fatalf("wynik: %+v", res)
	}

	h2, hg2, c2, _ := newHGHarness(t)
	h2.run()
	hg2.mu.Lock()
	c2.latest = 1
	hg2.mu.Unlock()
	if res := h2.run(); len(res.HGAlarms) != 1 || !strings.Contains(res.HGAlarms[0], "krotszy ciag") {
		t.Fatalf("wynik: %+v", res)
	}
}

func TestHourglassGenesisMustMatchList(t *testing.T) {
	h, _, c, _ := newHGHarness(t)
	c.genesisRoot = strings.Repeat("1", 64)
	if res := h.run(); res.HGConfirmed != 0 || len(res.HGAlarms) != 1 || !strings.Contains(res.HGAlarms[0], "inny genesis") {
		t.Fatalf("wynik: %+v", res)
	}
}

func TestHourglassNonCanonicalRecord(t *testing.T) {
	h, _, c, _ := newHGHarness(t)
	c.records[0] = append([]byte(" "), c.records[0]...)
	if res := h.run(); res.HGConfirmed != 0 || len(res.HGAlarms) != 1 || !strings.Contains(res.HGAlarms[0], "kanonicznym") {
		t.Fatalf("wynik: %+v", res)
	}
}

func TestHourglassSegmentFromTheFuture(t *testing.T) {
	h, _, _, _ := newHGHarness(t)
	h.clock = time.Date(2026, 11, 22, 23, 59, 0, 0, time.UTC) // odcinek 1 konczy sie o 00:00:05, tolerancja 30 s
	h.log.entries = h.log.entries[:0]
	if res := h.run(); res.HGConfirmed != 0 || len(res.HGAlarms) != 1 || !strings.Contains(res.HGAlarms[0], "pozniej niz zegar") {
		t.Fatalf("wynik: %+v", res)
	}
}

func TestHourglassConflictFromLog(t *testing.T) {
	h, hg, _, _ := newHGHarness(t)
	hg.confirmCode = http.StatusConflict
	res := h.run()
	if res.HGConfirmed != 2 || res.HGPending != 0 || len(res.HGAlarms) != 1 || !strings.Contains(res.HGAlarms[0], "nie zgadza sie") {
		t.Fatalf("wynik: %+v", res)
	}
}

func TestHourglassTemporaryFailureKeepsQueue(t *testing.T) {
	h, hg, _, _ := newHGHarness(t)
	hg.confirmCode = http.StatusServiceUnavailable
	if res := h.run(); res.HGConfirmed != 2 || res.HGDelivered != 0 || res.HGPending != 2 {
		t.Fatalf("wynik: %+v", res)
	}
	hg.mu.Lock()
	hg.confirmCode = 0
	hg.mu.Unlock()
	if res := h.run(); res.HGDelivered != 2 || res.HGPending != 0 || len(hg.confirmations(t)) != 2 {
		t.Fatalf("wynik: %+v", res)
	}
}

// Nowy klucz operatora: alarm; po decyzji (clear-hourglass-alarm) klucz przypina sie na nowo.
func TestHourglassKeyChangeNeedsOperator(t *testing.T) {
	h, hg, c, oldKey := newHGHarness(t)
	_, rec := canonical(t, c.records[1])
	other := ed25519.NewKeyFromSeed(make([]byte, 32))
	newKey := base64.StdEncoding.EncodeToString(other.Public().(ed25519.PublicKey))
	rec["key"] = newKey
	delete(rec, "sig")
	msg, err := hourglass.SigningMessage(rec)
	if err != nil {
		t.Fatal(err)
	}
	rec["sig"] = base64.StdEncoding.EncodeToString(ed25519.Sign(other, msg))
	c.records[1], _ = hourglass.Canonical(rec)

	res := h.run()
	if res.HGConfirmed != 1 || len(res.HGAlarms) != 1 || !strings.Contains(res.HGAlarms[0], "zmienil sie klucz") {
		t.Fatalf("wynik: %+v", res)
	}
	st, v, _ := h.r.Store.Load(nil)
	if st.Hourglass["example"].Key != oldKey {
		t.Fatal("klucz przypiety przed alarmem zmienil sie")
	}
	if msg := runner.ClearHourglassAlarm(st, "example"); !strings.Contains(msg, "zdjety alarm") {
		t.Fatal(msg)
	}
	if _, err := h.r.Store.Save(nil, st, v); err != nil {
		t.Fatal(err)
	}
	if res := h.run(); res.HGConfirmed != 1 || len(res.HGAlarms) != 0 || len(hg.confirmations(t)) != 2 {
		t.Fatalf("po decyzji operatora: %+v", res)
	}
	st, _, _ = h.r.Store.Load(nil)
	if st.Hourglass["example"].Key != newKey {
		t.Fatal("nowy klucz nie zostal przypiety")
	}
}

func TestHourglassOffAndMissing(t *testing.T) {
	h, hg, _, _ := newHGHarness(t)
	h.r.Cfg.HourglassOff = true
	if res := h.run(); res.HGConfirmed != 0 || len(hg.confirmations(t)) != 0 {
		t.Fatalf("wynik: %+v", res)
	}
	h2 := newHarness(t) // dziennik bez /api/hourglass: 404, nic do sprawdzania
	if res := h2.run(); !res.Signed || res.HGConfirmed != 0 || len(res.HGAlarms) != 0 {
		t.Fatalf("wynik: %+v", res)
	}
}
