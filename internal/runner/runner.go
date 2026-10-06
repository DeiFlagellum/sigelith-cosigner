// Package runner to jeden przebieg straznika (PROTOCOL.md, sekcja 3):
// pobierz nowe wpisy z publicznego dziennika, sprawdz je wedlug WLASNEGO
// zegara, dolicz do drzewa, podpisz stan i odeslij podpis do dziennika.
//
// Zasada „fail-stop": kazda anomalia (przerwany lancuch, czas cofajacy sie,
// wpis datowany wstecz albo z przyszlosci, serwer nie zgadza sie z podpisem)
// zapisuje alarm w stanie i WSTRZYMUJE straznika do recznej decyzji
// operatora. Straznik nigdy nie podpisuje „mimo wszystko".
package runner

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
	"net/url"
	"strconv"
	"strings"
	"time"

	"sigelith.org/cosigner/internal/cosign"
	"sigelith.org/cosigner/internal/logtree"
)

// Version trafia do User-Agent.
var Version = "dev"

// Config to stale ustawienia straznika.
type Config struct {
	LogURL    string        // np. https://sigelith.org
	Name      string        // nazwa straznika (cosign.NameRE)
	LateTol   time.Duration // spoznienie wpisu wzgledem poprzedniej obserwacji (domyslnie 30 s)
	EarlyTol  time.Duration // wpis „z przyszlosci" wzgledem zegara straznika (domyslnie 30 s)
	Heartbeat time.Duration // podpis bez nowych wpisow nie rzadziej niz co tyle (domyslnie 1 h)
	MaxPages  int           // stron po 1000 wpisow na przebieg (domyslnie 50)
	MaxOutbox int           // niedostarczonych podpisow w stanie (domyslnie 20)
}

func (c Config) withDefaults() Config {
	if c.LateTol == 0 {
		c.LateTol = 30 * time.Second
	}
	if c.EarlyTol == 0 {
		c.EarlyTol = 30 * time.Second
	}
	if c.Heartbeat == 0 {
		c.Heartbeat = time.Hour
	}
	if c.MaxPages == 0 {
		c.MaxPages = 50
	}
	if c.MaxOutbox == 0 {
		c.MaxOutbox = 20
	}
	c.LogURL = strings.TrimRight(c.LogURL, "/")
	return c
}

// State to wszystko, co straznik pamieta miedzy przebiegami.
type State struct {
	Key           string   `json:"key,omitempty"`  // wlasny klucz publiczny (wykrywa podmiane)
	Size          uint64   `json:"size"`           // lisci w drzewie
	Edges         []string `json:"edges"`          // krawedz drzewa (logtree.Tree.Edges)
	LastSeq       int64    `json:"last_seq"`       // ostatni wpis
	LastChainHash string   `json:"last_chain_hash"`
	LastUTC       string   `json:"last_utc"`
	ObservedAt    string   `json:"observed_at"` // chwila TUZ PRZED ostatnim pelnym pobraniem
	LastSigned    string   `json:"last_signed"`
	Alarm         string   `json:"alarm,omitempty"`
	Outbox        []string `json:"outbox"` // podpisy jeszcze nieprzyjete przez dziennik
}

// Store przechowuje stan (plik u operatora, DynamoDB w AWS).
type Store interface {
	Load(ctx context.Context) (*State, int64, error)
	// Save zapisuje stan, jesli od Load nikt go nie zmienil; zwraca nowa wersje.
	Save(ctx context.Context, st *State, version int64) (int64, error)
}

// Signer podpisuje kluczem straznika (plik albo KMS).
type Signer interface {
	PublicKey(ctx context.Context) (ed25519.PublicKey, error)
	Sign(ctx context.Context, msg []byte) ([]byte, error)
}

// Runner laczy konfiguracje, stan, klucz i siec.
type Runner struct {
	Cfg    Config
	Store  Store
	Signer Signer
	HTTP   *http.Client
	Now    func() time.Time
	Logf   func(format string, args ...any)
}

// Result opisuje przebieg (do dziennika zdarzen i odpowiedzi Lambdy).
type Result struct {
	NewEntries int    `json:"new_entries"`
	Size       uint64 `json:"size"`
	Signed     bool   `json:"signed"`
	Delivered  int    `json:"delivered"`
	Pending    int    `json:"pending"`
	Alarm      string `json:"alarm,omitempty"`
}

type entry struct {
	Seq       int64  `json:"seq"`
	Digest    string `json:"digest"`
	UTC       string `json:"utc"`
	ChainHash string `json:"chain_hash"`
	PrevChain string `json:"prev_chain"`
}

func (r *Runner) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

func (r *Runner) logf(format string, args ...any) {
	if r.Logf != nil {
		r.Logf(format, args...)
	}
}

func (r *Runner) client() *http.Client {
	if r.HTTP != nil {
		return r.HTTP
	}
	return &http.Client{Timeout: 15 * time.Second}
}

func (r *Runner) userAgent() string {
	return "sigelith-cosigner/" + Version + " (" + r.Cfg.Name + ")"
}

// fetch pobiera wpisy od `from`; complete=false, gdy zostaly nastepne strony.
func (r *Runner) fetch(ctx context.Context, cfg Config, from int64) ([]entry, bool, error) {
	var all []entry
	for page := 0; page < cfg.MaxPages; page++ {
		u := cfg.LogURL + "/api/proof/entries?from=" + strconv.FormatInt(from, 10) + "&limit=1000"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, false, err
		}
		req.Header.Set("User-Agent", r.userAgent())
		req.Header.Set("Accept", "application/json")
		resp, err := r.client().Do(req)
		if err != nil {
			return nil, false, err
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		if err != nil {
			return nil, false, err
		}
		if resp.StatusCode != http.StatusOK {
			return nil, false, fmt.Errorf("dziennik odpowiedzial %d na %s", resp.StatusCode, u)
		}
		var out struct {
			Entries []entry `json:"entries"`
			Next    *int64  `json:"next"`
		}
		if err := json.Unmarshal(data, &out); err != nil {
			return nil, false, fmt.Errorf("odpowiedz dziennika to nie JSON: %w", err)
		}
		all = append(all, out.Entries...)
		if out.Next == nil {
			return all, true, nil
		}
		if *out.Next <= from {
			return nil, false, errors.New("dziennik podal `next` nie dalej niz `from`")
		}
		from = *out.Next
	}
	return all, false, nil
}

// alarm zapisuje alarm w stanie (fail-stop) i zwraca blad.
func (r *Runner) alarm(ctx context.Context, st *State, version int64, at time.Time, msg string) (Result, error) {
	st.Alarm = msg + " [" + logtree.CanonicalUTC(at) + "]"
	r.logf("ALARM: %s", st.Alarm)
	if _, err := r.Store.Save(ctx, st, version); err != nil {
		r.logf("nie zapisano alarmu: %v", err)
	}
	return Result{Size: st.Size, Alarm: st.Alarm, Pending: len(st.Outbox)}, errors.New("ALARM: " + st.Alarm)
}

// RunOnce to jeden przebieg straznika.
func (r *Runner) RunOnce(ctx context.Context) (Result, error) {
	cfg := r.Cfg.withDefaults()
	if !cosign.NameRE.MatchString(cfg.Name) {
		return Result{}, errors.New("nazwa straznika: [a-z0-9-], do 32 znakow")
	}
	logURL, err := url.Parse(cfg.LogURL)
	if err != nil || logURL.Host == "" {
		return Result{}, fmt.Errorf("zly adres dziennika %q", cfg.LogURL)
	}
	st, version, err := r.Store.Load(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("stan: %w", err)
	}
	if st.Alarm != "" {
		return Result{Size: st.Size, Alarm: st.Alarm, Pending: len(st.Outbox)},
			errors.New("straznik wstrzymany (alarm): " + st.Alarm)
	}
	pub, err := r.Signer.PublicKey(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("klucz: %w", err)
	}
	keyB64 := base64.StdEncoding.EncodeToString(pub)
	if st.Key != "" && st.Key != keyB64 {
		return r.alarm(ctx, st, version, r.now(), "zmienil sie klucz straznika ("+st.Key+" -> "+keyB64+")")
	}
	st.Key = keyB64
	tree, err := logtree.Restore(st.Size, st.Edges)
	if err != nil {
		return r.alarm(ctx, st, version, r.now(), "uszkodzony stan drzewa: "+err.Error())
	}

	tStart := r.now()
	entries, complete, err := r.fetch(ctx, cfg, st.LastSeq+1)
	if err != nil {
		return Result{Size: st.Size, Pending: len(st.Outbox)}, fmt.Errorf("pobieranie wpisow: %w", err)
	}
	tEnd := r.now()

	prevChain, lastSeq := st.LastChainHash, st.LastSeq
	if st.Size == 0 {
		prevChain = logtree.Genesis
	}
	var prevUTC time.Time
	if st.LastUTC != "" {
		if prevUTC, err = logtree.ParseCanonical(st.LastUTC); err != nil {
			return r.alarm(ctx, st, version, tEnd, "uszkodzony stan: last_utc")
		}
	}
	var lower time.Time
	hasLower := st.ObservedAt != ""
	if hasLower {
		observed, err := logtree.ParseCanonical(st.ObservedAt)
		if err != nil {
			return r.alarm(ctx, st, version, tEnd, "uszkodzony stan: observed_at")
		}
		lower = observed.Add(-cfg.LateTol)
	}
	upper := tEnd.Add(cfg.EarlyTol)

	for _, e := range entries {
		at := fmt.Sprintf("wpis seq=%d", e.Seq)
		if e.Seq <= lastSeq {
			return r.alarm(ctx, st, version, tEnd, at+": numeracja nie rosnie")
		}
		if !logtree.IsHex64(e.Digest) || !logtree.IsHex64(e.ChainHash) || !logtree.IsHex64(e.PrevChain) {
			return r.alarm(ctx, st, version, tEnd, at+": zle pole digest/chain_hash/prev_chain")
		}
		ts, err := logtree.ParseCanonical(e.UTC)
		if err != nil {
			return r.alarm(ctx, st, version, tEnd, at+": "+err.Error())
		}
		if e.PrevChain != prevChain {
			return r.alarm(ctx, st, version, tEnd, at+": prev_chain nie wskazuje poprzedniego ogniwa — lancuch przerwany")
		}
		if logtree.ChainHash(prevChain, e.Digest, ts) != e.ChainHash {
			return r.alarm(ctx, st, version, tEnd, at+": chain_hash nie wynika z tresci wpisu")
		}
		if ts.Before(prevUTC) {
			return r.alarm(ctx, st, version, tEnd, at+": czas cofa sie wzgledem poprzedniego wpisu")
		}
		if ts.After(upper) {
			return r.alarm(ctx, st, version, tEnd, at+": czas "+e.UTC+" pozniejszy niz zegar straznika "+logtree.CanonicalUTC(tEnd))
		}
		if hasLower && ts.Before(lower) {
			return r.alarm(ctx, st, version, tEnd, at+": wpis datowany wstecz — czas "+e.UTC+
				", a o "+st.ObservedAt+" dziennika jeszcze bez niego straznik juz widzial")
		}
		tree.Append(logtree.EntryLeaf(e.Seq, e.Digest, ts))
		prevChain, lastSeq, prevUTC = e.ChainHash, e.Seq, ts
	}

	res := Result{NewEntries: len(entries), Size: tree.Size()}
	heartbeatDue := st.LastSigned == ""
	if !heartbeatDue {
		if last, err := logtree.ParseCanonical(st.LastSigned); err != nil || tEnd.Sub(last) >= cfg.Heartbeat {
			heartbeatDue = true
		}
	}
	if tree.Size() > 0 && (tree.Size() > st.Size || heartbeatDue) {
		root := tree.Root()
		body := cosign.Body{
			Log: logURL.Host, Cosigner: cfg.Name, Key: keyB64,
			Size: tree.Size(), Root: hex.EncodeToString(root[:]),
			LastSeq: lastSeq, LastChainHash: prevChain,
			Time: logtree.CanonicalUTC(tEnd),
		}
		if hasLower {
			body.Since = &cosign.Since{Size: st.Size, Time: st.ObservedAt}
		}
		msg, err := body.Message()
		if err != nil {
			return r.alarm(ctx, st, version, tEnd, "tresc podpisu: "+err.Error())
		}
		sig, err := r.Signer.Sign(ctx, msg)
		if err != nil {
			return Result{Size: st.Size, Pending: len(st.Outbox)}, fmt.Errorf("podpis: %w", err)
		}
		if !ed25519.Verify(pub, msg, sig) {
			return r.alarm(ctx, st, version, tEnd, "podpis nie pasuje do wlasnego klucza")
		}
		doc, err := body.Document(sig)
		if err != nil {
			return r.alarm(ctx, st, version, tEnd, "dokument podpisu: "+err.Error())
		}
		st.Outbox = append(st.Outbox, string(doc))
		if len(st.Outbox) > cfg.MaxOutbox {
			st.Outbox = st.Outbox[len(st.Outbox)-cfg.MaxOutbox:]
		}
		st.LastSigned = body.Time
		res.Signed = true
	}

	st.Size, st.Edges = tree.Size(), tree.Edges()
	st.LastSeq, st.LastChainHash = lastSeq, prevChain
	if !prevUTC.IsZero() {
		st.LastUTC = logtree.CanonicalUTC(prevUTC)
	}
	// Dolna granica przesuwa sie tylko po PELNYM pobraniu: wpisow, ktorych
	// jeszcze nie pobralismy, nie widzielismy — nie wolno ich uznac za mlodsze.
	if complete {
		st.ObservedAt = logtree.CanonicalUTC(tStart)
	}
	if version, err = r.Store.Save(ctx, st, version); err != nil {
		return res, fmt.Errorf("zapis stanu: %w", err)
	}

	delivered, alarmMsg := r.deliver(ctx, cfg, st)
	res.Delivered = delivered
	if delivered > 0 || alarmMsg != "" {
		if alarmMsg != "" {
			return r.alarm(ctx, st, version, r.now(), alarmMsg)
		}
		if _, err := r.Store.Save(ctx, st, version); err != nil {
			return res, fmt.Errorf("zapis stanu po wysylce: %w", err)
		}
	}
	res.Pending = len(st.Outbox)
	return res, nil
}

// deliver wysyla podpisy z kolejki do dziennika (POST /api/cosign).
func (r *Runner) deliver(ctx context.Context, cfg Config, st *State) (int, string) {
	delivered := 0
	var keep []string
	for i, doc := range st.Outbox {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.LogURL+"/api/cosign", bytes.NewReader([]byte(doc)))
		if err != nil {
			keep = append(keep, st.Outbox[i:]...)
			break
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", r.userAgent())
		resp, err := r.client().Do(req)
		if err != nil {
			r.logf("wysylka podpisu odlozona: %v", err)
			keep = append(keep, st.Outbox[i:]...)
			break
		}
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		resp.Body.Close()
		switch {
		case resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated:
			delivered++
		case resp.StatusCode == http.StatusConflict:
			st.Outbox = append(keep, st.Outbox[i:]...)
			return delivered, "dziennik nie zgadza sie z podpisanym stanem: " + strings.TrimSpace(string(detail))
		case resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusForbidden:
			r.logf("dziennik odrzucil podpis (%d): %s", resp.StatusCode, strings.TrimSpace(string(detail)))
		default:
			r.logf("wysylka podpisu odlozona (%d)", resp.StatusCode)
			keep = append(keep, st.Outbox[i:]...)
			st.Outbox = keep
			return delivered, ""
		}
	}
	st.Outbox = keep
	return delivered, ""
}
