package runner

// Klepsydra (PROTOCOL.md, sekcja 9). Po podpisie dziennika straznik bierze liste zegarow
// z /api/hourglass/clocks i dla kazdego sprawdza SAM kazdy nowy odcinek: dowod pracy
// sekwencyjnej, ziarno, ciaglosc od genesis i podpis operatora zegara. Za kazdy poprawny
// odcinek podpisuje potwierdzenie `sigelith-hourglass-confirm-v1` i wysyla je do dziennika.
//
// Alarm Klepsydry dotyczy TYLKO jednego zegara: zly odcinek, rozwidlenie, zmieniony genesis
// albo klucz operatora wstrzymuja potwierdzenia tego zegara do decyzji operatora straznika
// (clear-hourglass-alarm). Podpisy dziennika i pozostale zegary ida dalej.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"sigelith.org/cosigner/internal/cosign"
	"sigelith.org/cosigner/internal/hourglass"
	"sigelith.org/cosigner/internal/logtree"
)

// HGClock to wszystko, co straznik pamieta o jednym zegarze Klepsydry.
type HGClock struct {
	Genesis string `json:"genesis"`         // korzen genesis, przypiety przy pierwszym spotkaniu
	Key     string `json:"key,omitempty"`   // klucz operatora zegara, przypiety przy pierwszym odcinku
	J       int64  `json:"j"`               // ostatni sprawdzony odcinek (0 = tylko genesis)
	Root    string `json:"root"`            // jego korzen
	UTC     string `json:"utc"`             // jego utc_end (dla genesis: utc)
	Alarm   string `json:"alarm,omitempty"` // alarm tylko tego zegara
}

type clockInfo struct {
	Clock         string `json:"clock"`
	Operator      string `json:"operator"`
	GenesisRoot   string `json:"genesis_root"`
	LatestSegment int64  `json:"latest_segment"`
	LatestRoot    string `json:"latest_root"`
}

const maxProofBytes = hourglass.MaxT * hourglass.MaxN * hourglass.LabelSize

func (r *Runner) get(ctx context.Context, u string, limit int64) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", r.userAgent())
	resp, err := r.client().Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, 0, err
	}
	if int64(len(data)) > limit {
		return nil, 0, fmt.Errorf("odpowiedz %s dluzsza niz %d bajtow", u, limit)
	}
	return data, resp.StatusCode, nil
}

// hourglass to krok Klepsydry w przebiegu straznika. Bledy sieci tylko odkladaja prace do
// nastepnego przebiegu; anomalie zapisuja alarm zegara. Nigdy nie zatrzymuje podpisow dziennika.
func (r *Runner) hourglass(ctx context.Context, cfg Config, st *State, version *int64, pub ed25519.PublicKey,
	keyB64, logHost string, started time.Time, res *Result) {
	if cfg.HourglassOff {
		return
	}
	changed := false
	// Siec i podpisy Klepsydry maja wlasny, krotszy termin (Lambda: 30 s na caly przebieg),
	// zeby zapis stanu ponizej zawsze zdazyl - on idzie na kontekscie przebiegu.
	hctx, cancel := context.WithTimeout(ctx, cfg.HGBudget+8*time.Second-r.now().Sub(started))
	defer cancel()
	defer func() {
		res.HGPending = len(st.HGOutbox)
		for name, hc := range st.Hourglass {
			if hc.Alarm != "" {
				res.HGAlarms = append(res.HGAlarms, name+": "+hc.Alarm)
			}
		}
		if changed {
			v, err := r.Store.Save(ctx, st, *version)
			if err != nil {
				r.logf("klepsydra: zapis stanu: %v", err)
				return
			}
			*version = v
		}
	}()

	if len(st.HGOutbox) < cfg.HGMaxOutbox {
		data, status, err := r.get(hctx, cfg.LogURL+"/api/hourglass/clocks", 1<<20)
		switch {
		case err != nil:
			r.logf("klepsydra: lista zegarow: %v", err)
		case status == http.StatusNotFound:
			// dziennik bez Klepsydry - nie ma czego sprawdzac
		case status != http.StatusOK:
			r.logf("klepsydra: lista zegarow: dziennik odpowiedzial %d", status)
		default:
			var list struct {
				Clocks []clockInfo `json:"clocks"`
			}
			if err := json.Unmarshal(data, &list); err != nil {
				r.logf("klepsydra: lista zegarow to nie JSON: %v", err)
				break
			}
			if st.Hourglass == nil {
				st.Hourglass = map[string]*HGClock{}
			}
			for _, c := range list.Clocks {
				if !cosign.ClockRE.MatchString(c.Clock) {
					r.logf("klepsydra: pomijam zegar o nazwie %q", c.Clock)
					continue
				}
				n, ch := r.checkClock(hctx, cfg, st, c, pub, keyB64, logHost, started)
				res.HGConfirmed += n
				changed = changed || ch
			}
		}
	}
	delivered, ch := r.deliverHG(hctx, cfg, st)
	res.HGDelivered = delivered
	changed = changed || ch
}

func (r *Runner) hgAlarm(st *State, name, msg string) {
	hc := st.Hourglass[name]
	if hc == nil {
		hc = &HGClock{}
		st.Hourglass[name] = hc
	}
	if hc.Alarm == "" {
		hc.Alarm = msg + " [" + logtree.CanonicalUTC(r.now()) + "]"
		r.logf("ALARM KLEPSYDRY (zegar %s): %s", name, hc.Alarm)
	}
}

// checkClock sprawdza nowe odcinki jednego zegara; zwraca liczbe potwierdzen i czy stan sie zmienil.
func (r *Runner) checkClock(ctx context.Context, cfg Config, st *State, c clockInfo, pub ed25519.PublicKey,
	keyB64, logHost string, started time.Time) (int, bool) {
	base := cfg.LogURL + "/api/hourglass/" + c.Clock
	hc := st.Hourglass[c.Clock]
	if hc != nil && hc.Alarm != "" {
		return 0, false
	}
	changed := false
	if hc == nil {
		raw, status, err := r.get(ctx, base+"/genesis", 1<<16)
		if err != nil || status != http.StatusOK {
			r.logf("klepsydra %s: genesis niedostepny (%v, %d)", c.Clock, err, status)
			return 0, false
		}
		g, err := hourglass.DecodeObject(raw)
		var phi [32]byte
		if err == nil {
			phi, err = hourglass.GenesisRoot(g)
		}
		if err != nil {
			r.hgAlarm(st, c.Clock, "genesis niezgodny ze specyfikacja: "+err.Error())
			return 0, true
		}
		if canon, _ := hourglass.Canonical(g); !bytes.Equal(canon, raw) {
			r.hgAlarm(st, c.Clock, "genesis nie jest kanonicznym JSON")
			return 0, true
		}
		if hex.EncodeToString(phi[:]) != c.GenesisRoot || g["operator"] != c.Operator {
			r.hgAlarm(st, c.Clock, "lista zegarow podaje inny genesis albo operatora niz plik genesis")
			return 0, true
		}
		hc = &HGClock{Genesis: c.GenesisRoot, Root: c.GenesisRoot, UTC: g["utc"].(string)}
		st.Hourglass[c.Clock] = hc
		changed = true
		r.logf("klepsydra %s: przypiety genesis %s (operator %s)", c.Clock, hc.Genesis, c.Operator)
	}
	if c.GenesisRoot != hc.Genesis {
		r.hgAlarm(st, c.Clock, "zmienil sie genesis zegara ("+hc.Genesis+" -> "+c.GenesisRoot+")")
		return 0, true
	}
	if c.LatestSegment < hc.J {
		r.hgAlarm(st, c.Clock, fmt.Sprintf("dziennik pokazuje krotszy ciag: ostatni odcinek %d, a straznik sprawdzil %d",
			c.LatestSegment, hc.J))
		return 0, true
	}
	if c.LatestSegment == hc.J && c.LatestRoot != hc.Root {
		r.hgAlarm(st, c.Clock, fmt.Sprintf("rozwidlenie: odcinek %d ma teraz korzen %s, a sprawdzony mial %s",
			hc.J, c.LatestRoot, hc.Root))
		return 0, true
	}
	confirmed := 0
	for hc.J < c.LatestSegment && confirmed < cfg.HGMaxSegments && len(st.HGOutbox) < cfg.HGMaxOutbox &&
		r.now().Sub(started) < cfg.HGBudget {
		j := hc.J + 1
		u := base + "/segments/" + strconv.FormatInt(j, 10)
		raw, status, err := r.get(ctx, u, 1<<16)
		if err != nil || status != http.StatusOK {
			r.logf("klepsydra %s: odcinek %d niedostepny (%v, %d)", c.Clock, j, err, status)
			break
		}
		proof, status, err := r.get(ctx, u+"/proof", maxProofBytes)
		if err != nil || status != http.StatusOK {
			r.logf("klepsydra %s: dowod odcinka %d niedostepny (%v, %d)", c.Clock, j, err, status)
			break
		}
		rec, err := hourglass.DecodeObject(raw)
		if err != nil {
			r.hgAlarm(st, c.Clock, fmt.Sprintf("odcinek %d: %v", j, err))
			return confirmed, true
		}
		if canon, err := hourglass.Canonical(rec); err != nil || !bytes.Equal(canon, raw) {
			r.hgAlarm(st, c.Clock, fmt.Sprintf("odcinek %d: opublikowany plik nie jest kanonicznym JSON", j))
			return confirmed, true
		}
		keys := []string{hc.Key}
		if hc.Key == "" {
			// pierwszy odcinek: klucz z rekordu, po sprawdzeniu przypiety na stale
			k, _ := rec["key"].(string)
			keys = []string{k}
		} else if k, _ := rec["key"].(string); k != hc.Key {
			r.hgAlarm(st, c.Clock, fmt.Sprintf("odcinek %d: zmienil sie klucz operatora (%s -> %s)", j, hc.Key, k))
			return confirmed, true
		}
		prev, _ := hex.DecodeString(hc.Root)
		seg, err := hourglass.CheckSegment(rec, proof, prev, hc.UTC, hourglass.Options{Signed: true, Keys: keys})
		if err == nil && seg.J != j {
			err = fmt.Errorf("pod adresem odcinka %d lezy rekord odcinka %d", j, seg.J)
		}
		if err != nil {
			r.hgAlarm(st, c.Clock, fmt.Sprintf("odcinek %d NIE przechodzi sprawdzenia: %v", j, err))
			return confirmed, true
		}
		end, err := logtree.ParseCanonical(seg.UTCEnd)
		if err != nil || end.After(r.now().Add(cfg.EarlyTol)) {
			r.hgAlarm(st, c.Clock, fmt.Sprintf("odcinek %d konczy sie %s, pozniej niz zegar straznika %s", j,
				seg.UTCEnd, logtree.CanonicalUTC(r.now())))
			return confirmed, true
		}
		sum := sha256.Sum256(raw)
		conf := cosign.Confirmation{
			Log: logHost, Cosigner: cfg.Name, Key: keyB64, Clock: c.Clock, Genesis: hc.Genesis,
			J: j, Root: seg.Root, Record: hex.EncodeToString(sum[:]), Time: logtree.CanonicalUTC(r.now()),
		}
		msg, err := conf.Message()
		if err != nil {
			r.logf("klepsydra %s: tresc potwierdzenia: %v", c.Clock, err)
			break
		}
		sig, err := r.Signer.Sign(ctx, msg)
		if err != nil {
			r.logf("klepsydra %s: podpis: %v", c.Clock, err)
			break
		}
		if !ed25519.Verify(pub, msg, sig) {
			r.logf("klepsydra %s: podpis nie pasuje do wlasnego klucza", c.Clock)
			break
		}
		doc, err := conf.Document(sig)
		if err != nil {
			r.logf("klepsydra %s: dokument potwierdzenia: %v", c.Clock, err)
			break
		}
		st.HGOutbox = append(st.HGOutbox, string(doc))
		hc.J, hc.Root, hc.UTC = j, seg.Root, seg.UTCEnd
		if hc.Key == "" {
			hc.Key = seg.Key
		}
		confirmed++
		changed = true
		r.logf("klepsydra %s: odcinek %d poprawny, potwierdzony", c.Clock, j)
	}
	return confirmed, changed
}

// deliverHG wysyla potwierdzenia z kolejki (POST /api/hourglass/confirm).
func (r *Runner) deliverHG(ctx context.Context, cfg Config, st *State) (int, bool) {
	if len(st.HGOutbox) == 0 {
		return 0, false
	}
	delivered := 0
	before := len(st.HGOutbox)
	var keep []string
	for i, doc := range st.HGOutbox {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.LogURL+"/api/hourglass/confirm",
			strings.NewReader(doc))
		if err != nil {
			keep = append(keep, st.HGOutbox[i:]...)
			break
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", r.userAgent())
		resp, err := r.client().Do(req)
		if err != nil {
			r.logf("klepsydra: wysylka potwierdzenia odlozona: %v", err)
			keep = append(keep, st.HGOutbox[i:]...)
			break
		}
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		resp.Body.Close()
		switch code := resp.StatusCode; {
		case code == http.StatusOK || code == http.StatusCreated:
			delivered++
		case code == http.StatusConflict:
			var d struct {
				Clock string `json:"clock"`
				J     int64  `json:"j"`
			}
			_ = json.Unmarshal([]byte(doc), &d)
			if cosign.ClockRE.MatchString(d.Clock) {
				if st.Hourglass == nil {
					st.Hourglass = map[string]*HGClock{}
				}
				r.hgAlarm(st, d.Clock, fmt.Sprintf("dziennik nie zgadza sie z potwierdzonym odcinkiem %d: %s",
					d.J, strings.TrimSpace(string(detail))))
			}
		case code == http.StatusBadRequest || code == http.StatusForbidden:
			r.logf("klepsydra: dziennik odrzucil potwierdzenie (%d): %s", code, strings.TrimSpace(string(detail)))
		default:
			r.logf("klepsydra: wysylka potwierdzenia odlozona (%d)", code)
			keep = append(keep, st.HGOutbox[i:]...)
			st.HGOutbox = keep
			return delivered, len(keep) != before
		}
	}
	st.HGOutbox = keep
	return delivered, len(keep) != before
}

// ClearHourglassAlarm zdejmuje alarm zegara po decyzji operatora straznika. Zapomina tez
// przypiety klucz operatora zegara (nastepny odcinek przypnie go na nowo - tak przechodzi
// wymiana klucza), ale NIE pozycje w ciagu: zmieniona historia zegara wywola alarm ponownie.
func ClearHourglassAlarm(st *State, clock string) string {
	hc := st.Hourglass[clock]
	if hc == nil || hc.Alarm == "" {
		return "zegar " + clock + ": alarmu nie ma"
	}
	was := hc.Alarm
	hc.Alarm, hc.Key = "", ""
	if hc.Genesis == "" {
		// alarm przy pierwszym spotkaniu (zly genesis): nastepny przebieg zacznie od genesis
		delete(st.Hourglass, clock)
	}
	return "zegar " + clock + ": zdjety alarm: " + was
}
