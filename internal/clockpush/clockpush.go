// Package clockpush publikuje zegar Klepsydry niezaleznego operatora (PROTOCOL.md,
// sekcja 10). Prover Klepsydry zapisuje genesis.json i rekordy odcinkow BEZ podpisu;
// klucza nigdy nie ma (sigelith-hourglass, HOURGLASS D16). Ten program czyta jego katalog
// tylko do odczytu, sprawdza kazdy rekord ta sama implementacja co straznik (dowod, ziarno,
// ciaglosc), podpisuje go kluczem zegara i wysyla z dowodem do dziennika Sigelith
// (POST /api/hourglass/push). Dziennik sprawdza rekord jeszcze raz kluczem przypietym
// u siebie, stempluje go i rozdaje - podrobic go nie moze.
//
// Program nie pamieta niczego miedzy przebiegami: pozycje bierze z listy zegarow dziennika
// i porownuje ja z wlasnymi plikami. Podpis Ed25519 jest deterministyczny, wiec ponowne
// wyslanie tego samego odcinka daje te same bajty.
package clockpush

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sigelith.org/cosigner/internal/cosign"
	"sigelith.org/cosigner/internal/hourglass"
)

// Signer podpisuje kluczem zegara (plik clock.key; ten sam typ co klucz straznika).
type Signer interface {
	PublicKey(ctx context.Context) (ed25519.PublicKey, error)
	Sign(ctx context.Context, msg []byte) ([]byte, error)
}

// Config to stale ustawienia publikacji.
type Config struct {
	LogURL      string // np. https://sigelith.org
	Clock       string // nazwa zegara w dzienniku (cosign.ClockRE), np. konveria
	Dir         string // katalog provera: genesis.json, segments/<j>.json i <j>.proof
	MaxSegments int    // odcinkow na przebieg (domyslnie 20)
	Version     string // do User-Agent
}

// Pusher laczy konfiguracje, klucz zegara i siec.
type Pusher struct {
	Cfg    Config
	Signer Signer
	HTTP   *http.Client
	Logf   func(format string, args ...any)
}

// Result opisuje przebieg.
type Result struct {
	Genesis bool   `json:"genesis,omitempty"` // wyslany genesis
	Pushed  int    `json:"pushed"`            // wyslane odcinki
	Latest  int64  `json:"latest"`            // ostatni odcinek w dzienniku po przebiegu
	Waiting string `json:"waiting,omitempty"` // na co czeka (nie blad)
}

func (p *Pusher) logf(format string, args ...any) {
	if p.Logf != nil {
		p.Logf(format, args...)
	}
}

func (p *Pusher) client() *http.Client {
	if p.HTTP != nil {
		return p.HTTP
	}
	return &http.Client{Timeout: 60 * time.Second}
}

func (p *Pusher) do(ctx context.Context, method, u string, body []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("User-Agent", "sigelith-cosigner/"+p.Cfg.Version+" (clock "+p.Cfg.Clock+")")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := p.client().Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, data, err
}

type local struct {
	dir string
}

func (l local) genesis() ([]byte, map[string]any, error) {
	raw, err := os.ReadFile(filepath.Join(l.dir, "genesis.json"))
	if err != nil {
		return nil, nil, err
	}
	g, err := hourglass.DecodeObject(raw)
	if err != nil {
		return nil, nil, err
	}
	return raw, g, nil
}

// segment czyta rekord j provera (bez podpisu) i jego dowod; os.ErrNotExist = jeszcze nie ma.
func (l local) segment(j int64) (map[string]any, []byte, error) {
	name := filepath.Join(l.dir, "segments", fmt.Sprintf("%06d", j))
	raw, err := os.ReadFile(name + ".json")
	if err != nil {
		return nil, nil, err
	}
	rec, err := hourglass.DecodeObject(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("odcinek %d: %w", j, err)
	}
	file, err := hourglass.ProofFile(rec)
	if err != nil {
		return nil, nil, fmt.Errorf("odcinek %d: %w", j, err)
	}
	proof, err := os.ReadFile(filepath.Join(l.dir, "segments", file))
	if err != nil {
		return nil, nil, err
	}
	return rec, proof, nil
}

type clockInfo struct {
	Clock         string `json:"clock"`
	GenesisRoot   string `json:"genesis_root"`
	LatestSegment int64  `json:"latest_segment"`
	LatestRoot    string `json:"latest_root"`
}

// RunOnce to jeden przebieg: genesis, jesli dziennik go nie ma, potem kolejne odcinki.
func (p *Pusher) RunOnce(ctx context.Context) (Result, error) {
	cfg := p.Cfg
	cfg.LogURL = strings.TrimRight(cfg.LogURL, "/")
	if cfg.MaxSegments == 0 {
		cfg.MaxSegments = 20
	}
	if !cosign.ClockRE.MatchString(cfg.Clock) {
		return Result{}, errors.New("nazwa zegara: [a-z0-9-], do 32 znakow")
	}
	src := local{dir: cfg.Dir}
	graw, g, err := src.genesis()
	if errors.Is(err, os.ErrNotExist) {
		return Result{Waiting: "brak genesis.json - prover jeszcze nie wystartowal"}, nil
	}
	if err != nil {
		return Result{}, fmt.Errorf("genesis: %w", err)
	}
	phi, err := hourglass.GenesisRoot(g)
	if err != nil {
		return Result{}, fmt.Errorf("genesis provera: %w", err)
	}
	if canon, _ := hourglass.Canonical(g); !bytes.Equal(canon, graw) {
		return Result{}, errors.New("genesis provera nie jest kanonicznym JSON")
	}
	pub, err := p.Signer.PublicKey(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("klucz zegara: %w", err)
	}
	keyB64 := base64.StdEncoding.EncodeToString(pub)

	status, data, err := p.do(ctx, http.MethodGet, cfg.LogURL+"/api/hourglass/clocks", nil)
	if err != nil || status != http.StatusOK {
		return Result{}, fmt.Errorf("lista zegarow: %v (%d)", err, status)
	}
	var list struct {
		Clocks []clockInfo `json:"clocks"`
	}
	if err := json.Unmarshal(data, &list); err != nil {
		return Result{}, fmt.Errorf("lista zegarow to nie JSON: %w", err)
	}
	var info *clockInfo
	for i := range list.Clocks {
		if list.Clocks[i].Clock == cfg.Clock {
			info = &list.Clocks[i]
		}
	}
	res := Result{}
	if info == nil {
		body, _ := hourglass.Canonical(map[string]any{"clock": cfg.Clock, "genesis": g})
		status, detail, err := p.do(ctx, http.MethodPost, cfg.LogURL+"/api/hourglass/push", body)
		switch {
		case err != nil:
			return res, fmt.Errorf("wysylka genesis: %w", err)
		case status == http.StatusCreated || status == http.StatusOK:
			p.logf("genesis zegara %s opublikowany (phi_0 %x)", cfg.Clock, phi)
			res.Genesis = true
			info = &clockInfo{Clock: cfg.Clock, GenesisRoot: hex.EncodeToString(phi[:]),
				LatestRoot: hex.EncodeToString(phi[:])}
		case status == http.StatusForbidden:
			res.Waiting = fmt.Sprintf("dziennik jeszcze nie zna tego zegara: wyslij Sigelith klucz %s i phi_0 %x (%s)",
				keyB64, phi, strings.TrimSpace(string(detail)))
			return res, nil
		default:
			return res, fmt.Errorf("dziennik odrzucil genesis (%d): %s", status, strings.TrimSpace(string(detail)))
		}
	}
	if info.GenesisRoot != hex.EncodeToString(phi[:]) {
		return res, fmt.Errorf("dziennik ma inny genesis zegara %s (%s) niz prover (%x) - nic nie wysylam",
			cfg.Clock, info.GenesisRoot, phi)
	}
	res.Latest = info.LatestSegment

	// Pozycja dziennika musi byc pozycja provera: ten sam korzen ostatniego odcinka.
	prevRoot, prevUTC := phi[:], g["utc"].(string)
	if info.LatestSegment > 0 {
		rec, _, err := src.segment(info.LatestSegment)
		if err != nil {
			return res, fmt.Errorf("dziennik ma odcinek %d, prover go nie ma: %v", info.LatestSegment, err)
		}
		if rec["root"] != info.LatestRoot {
			return res, fmt.Errorf("ROZWIDLENIE: odcinek %d w dzienniku ma korzen %s, u provera %v - nic nie wysylam",
				info.LatestSegment, info.LatestRoot, rec["root"])
		}
		prevRoot, _ = hex.DecodeString(info.LatestRoot)
		prevUTC, _ = rec["utc_end"].(string)
	} else if info.LatestRoot != info.GenesisRoot {
		return res, fmt.Errorf("lista zegarow: korzen %s przy samym genesis", info.LatestRoot)
	}

	for j := info.LatestSegment + 1; res.Pushed < cfg.MaxSegments; j++ {
		rec, proof, err := src.segment(j)
		if errors.Is(err, os.ErrNotExist) {
			break
		}
		if err != nil {
			return res, err
		}
		if _, err := hourglass.CheckSegment(rec, proof, prevRoot, prevUTC, hourglass.Options{}); err != nil {
			return res, fmt.Errorf("rekord provera NIE przechodzi sprawdzenia - nie podpisuje: %w", err)
		}
		rec["key"] = keyB64
		msg, err := hourglass.SigningMessage(rec)
		if err != nil {
			return res, err
		}
		sig, err := p.Signer.Sign(ctx, msg)
		if err != nil {
			return res, fmt.Errorf("podpis: %w", err)
		}
		rec["sig"] = base64.StdEncoding.EncodeToString(sig)
		seg, err := hourglass.CheckSegment(rec, proof, prevRoot, prevUTC,
			hourglass.Options{Signed: true, Keys: []string{keyB64}})
		if err != nil {
			return res, fmt.Errorf("podpisany rekord nie przechodzi sprawdzenia: %w", err)
		}
		body, err := hourglass.Canonical(map[string]any{"clock": cfg.Clock, "record": rec,
			"proof": base64.StdEncoding.EncodeToString(proof)})
		if err != nil {
			return res, err
		}
		status, detail, err := p.do(ctx, http.MethodPost, cfg.LogURL+"/api/hourglass/push", body)
		if err != nil {
			return res, fmt.Errorf("wysylka odcinka %d: %w", j, err)
		}
		if status != http.StatusCreated && status != http.StatusOK {
			return res, fmt.Errorf("dziennik odrzucil odcinek %d (%d): %s", j, status, strings.TrimSpace(string(detail)))
		}
		p.logf("odcinek %d zegara %s opublikowany", j, cfg.Clock)
		res.Pushed++
		res.Latest = j
		prevRoot, _ = hex.DecodeString(seg.Root)
		prevUTC = seg.UTCEnd
	}
	return res, nil
}
