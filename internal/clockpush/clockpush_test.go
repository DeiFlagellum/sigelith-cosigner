package clockpush

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"sigelith.org/cosigner/internal/hourglass"
)

type keySigner struct{ key ed25519.PrivateKey }

func (k keySigner) PublicKey(context.Context) (ed25519.PublicKey, error) {
	return k.key.Public().(ed25519.PublicKey), nil
}

func (k keySigner) Sign(_ context.Context, msg []byte) ([]byte, error) {
	return ed25519.Sign(k.key, msg), nil
}

// fakeLog przyjmuje genesis i odcinki jednego zegara (POST /api/hourglass/push).
type fakeLog struct {
	mu         sync.Mutex
	pinned     bool
	genesis    []byte
	phi        string
	records    [][]byte
	roots      []string
	rootPatch  string
	pushBodies int
}

func (f *fakeLog) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/hourglass/clocks":
		list := []map[string]any{}
		if f.genesis != nil {
			root := f.phi
			if n := len(f.roots); n > 0 {
				root = f.roots[n-1]
			}
			if f.rootPatch != "" {
				root = f.rootPatch
			}
			list = append(list, map[string]any{"clock": "test", "operator": "example.org", "genesis_root": f.phi,
				"latest_segment": len(f.records), "latest_root": root})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"clocks": list})
	case r.Method == http.MethodPost && r.URL.Path == "/api/hourglass/push":
		f.pushBodies++
		if !f.pinned {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"unknown clock"}`))
			return
		}
		raw, _ := io.ReadAll(r.Body)
		body, err := hourglass.DecodeObject(raw)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if g, ok := body["genesis"].(map[string]any); ok {
			phi, err := hourglass.GenesisRoot(g)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			f.genesis, _ = hourglass.Canonical(g)
			f.phi = hex.EncodeToString(phi[:])
			w.WriteHeader(http.StatusCreated)
			return
		}
		rec := body["record"].(map[string]any)
		data, _ := hourglass.Canonical(rec)
		f.records = append(f.records, data)
		f.roots = append(f.roots, rec["root"].(string))
		w.WriteHeader(http.StatusCreated)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

type chainVectors struct {
	V1 struct {
		Chain struct {
			Genesis   json.RawMessage                 `json:"genesis"`
			TestKey   struct{ Secret, Public string } `json:"test_key"`
			Segments  []json.RawMessage               `json:"segments"`
			Proofs    []string                        `json:"proofs"`
			Unsigned1 json.RawMessage                 `json:"unsigned_1"`
		} `json:"chain"`
	} `json:"v1"`
}

func canon(t *testing.T, raw []byte) ([]byte, map[string]any) {
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

// proverDir zapisuje genesis i odcinki BEZ podpisu - tak jak prover Klepsydry.
func proverDir(t *testing.T) (string, chainVectors, [][]byte) {
	t.Helper()
	data, err := os.ReadFile("../hourglass/testdata/hourglass-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v chainVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "segments"), 0o755); err != nil {
		t.Fatal(err)
	}
	g, _ := canon(t, v.V1.Chain.Genesis)
	if err := os.WriteFile(filepath.Join(dir, "genesis.json"), g, 0o644); err != nil {
		t.Fatal(err)
	}
	var signed [][]byte
	for i, raw := range v.V1.Chain.Segments {
		s, rec := canon(t, raw)
		signed = append(signed, s)
		delete(rec, "key")
		delete(rec, "sig")
		unsigned, _ := hourglass.Canonical(rec)
		proof, _ := hex.DecodeString(v.V1.Chain.Proofs[i])
		name := filepath.Join(dir, "segments", rec["proof"].(map[string]any)["file"].(string))
		if err := os.WriteFile(name, proof, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(strings.TrimSuffix(name, ".proof")+".json", unsigned, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir, v, signed
}

func newPusher(t *testing.T, dir string, v chainVectors) (*Pusher, *fakeLog) {
	t.Helper()
	f := &fakeLog{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	seed, _ := hex.DecodeString(v.V1.Chain.TestKey.Secret)
	return &Pusher{
		Cfg:    Config{LogURL: srv.URL, Clock: "test", Dir: dir, Version: "test"},
		Signer: keySigner{ed25519.NewKeyFromSeed(seed)},
	}, f
}

func TestWaitsForProverAndForPinning(t *testing.T) {
	dir, v, _ := proverDir(t)
	p, f := newPusher(t, t.TempDir(), v)
	if res, err := p.RunOnce(context.Background()); err != nil || !strings.Contains(res.Waiting, "prover") {
		t.Fatalf("bez genesis: %+v %v", res, err)
	}
	p.Cfg.Dir = dir
	res, err := p.RunOnce(context.Background())
	if err != nil || !strings.Contains(res.Waiting, "nie zna") || !strings.Contains(res.Waiting, v.V1.Chain.TestKey.Public) {
		t.Fatalf("przed przypieciem: %+v %v", res, err)
	}
	if f.genesis != nil || f.pushBodies != 1 {
		t.Fatal("dziennik przyjal genesis nieprzypietego zegara")
	}
}

// Rekordy podpisane tym programem kluczem testowym sa bajt w bajt rekordami z wektorow.
func TestPushesGenesisAndSignedSegments(t *testing.T) {
	dir, v, signed := proverDir(t)
	p, f := newPusher(t, dir, v)
	f.pinned = true
	res, err := p.RunOnce(context.Background())
	if err != nil || !res.Genesis || res.Pushed != 2 || res.Latest != 2 {
		t.Fatalf("wynik: %+v %v", res, err)
	}
	for i := range signed {
		if string(f.records[i]) != string(signed[i]) {
			t.Fatalf("odcinek %d inny niz w wektorach:\n%s\n%s", i+1, f.records[i], signed[i])
		}
	}
	if res, err := p.RunOnce(context.Background()); err != nil || res.Pushed != 0 || res.Genesis {
		t.Fatalf("drugi przebieg: %+v %v", res, err)
	}
}

func TestStopsOnForkAndOnBadRecord(t *testing.T) {
	dir, v, _ := proverDir(t)
	p, f := newPusher(t, dir, v)
	f.pinned = true
	p.Cfg.MaxSegments = 1
	if res, err := p.RunOnce(context.Background()); err != nil || res.Pushed != 1 {
		t.Fatalf("wynik: %+v %v", res, err)
	}
	f.rootPatch = strings.Repeat("0", 64)
	if _, err := p.RunOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "ROZWIDLENIE") {
		t.Fatalf("rozwidlenie przeszlo: %v", err)
	}
	f.rootPatch = ""
	proof := filepath.Join(dir, "segments", "000002.proof")
	data, _ := os.ReadFile(proof)
	data[10] ^= 1
	if err := os.WriteFile(proof, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := p.RunOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "nie podpisuje") {
		t.Fatalf("zly rekord przeszedl: %v", err)
	}
	if len(f.records) != 1 {
		t.Fatal("wyslany zly odcinek")
	}
}

func TestPublicKeyIsTheVectorKey(t *testing.T) {
	_, v, _ := proverDir(t)
	seed, _ := hex.DecodeString(v.V1.Chain.TestKey.Secret)
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if base64.StdEncoding.EncodeToString(pub) != v.V1.Chain.TestKey.Public {
		t.Fatal("klucz testowy z wektorow nie pasuje do ziarna")
	}
}
