package cosign

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"

	"sigelith.org/cosigner/internal/logtree"
)

// HourglassV1 to wersja potwierdzenia odcinka Klepsydry i domena jego podpisu
// (PROTOCOL.md, sekcja 9).
const HourglassV1 = "sigelith-hourglass-confirm-v1"

// ClockRE: nazwa zegara Klepsydry na serwerze dziennika, np. sigelith.
var ClockRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// Confirmation to tresc potwierdzenia (bez `sig`): straznik sam sprawdzil odcinek
// `J` zegara `Clock` i caly ciag od genesis do niego.
type Confirmation struct {
	Log      string // host dziennika, ktory publikuje zegar, np. sigelith.org
	Cosigner string // nazwa straznika, NameRE
	Key      string // klucz publiczny Ed25519 straznika, base64 (32 bajty)
	Clock    string // nazwa zegara, ClockRE
	Genesis  string // korzen genesis phi_0, hex
	J        int64  // numer odcinka, od 1
	Root     string // korzen odcinka phi_J, hex
	Record   string // SHA-256 opublikowanych bajtow rekordu odcinka, hex
	Time     string // zegar straznika po sprawdzeniu (canonical_utc)
}

func (c Confirmation) object() map[string]any {
	return map[string]any{
		"v":        HourglassV1,
		"log":      c.Log,
		"cosigner": c.Cosigner,
		"key":      c.Key,
		"clock":    c.Clock,
		"genesis":  c.Genesis,
		"j":        c.J,
		"root":     c.Root,
		"record":   c.Record,
		"time":     c.Time,
	}
}

// Validate sprawdza tresc przed podpisem.
func (c Confirmation) Validate() error {
	if c.Log == "" || !NameRE.MatchString(c.Cosigner) || !ClockRE.MatchString(c.Clock) {
		return errors.New("log, cosigner i clock sa wymagane ([a-z0-9-], do 32 znakow)")
	}
	if raw, err := base64.StdEncoding.DecodeString(c.Key); err != nil || len(raw) != ed25519.PublicKeySize {
		return errors.New("key: klucz Ed25519 w base64")
	}
	if c.J < 1 || c.J >= 1<<53 {
		return errors.New("j: liczba calkowita od 1")
	}
	if !logtree.IsHex64(c.Genesis) || !logtree.IsHex64(c.Root) || !logtree.IsHex64(c.Record) {
		return errors.New("genesis, root i record: 64 znaki hex")
	}
	if _, err := logtree.ParseCanonical(c.Time); err != nil {
		return fmt.Errorf("time: %w", err)
	}
	return nil
}

// Message to podpisywane bajty: ASCII("sigelith-hourglass-confirm-v1|") || JCS(tresc).
func (c Confirmation) Message() ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	body, err := Canonical(c.object())
	if err != nil {
		return nil, err
	}
	return append([]byte(HourglassV1+"|"), body...), nil
}

// Document to potwierdzenie gotowe do wyslania i archiwizacji: JCS(tresc + sig).
func (c Confirmation) Document(sig []byte) ([]byte, error) {
	if len(sig) != ed25519.SignatureSize {
		return nil, errors.New("podpis Ed25519 ma 64 bajty")
	}
	obj := c.object()
	obj["sig"] = base64.StdEncoding.EncodeToString(sig)
	return Canonical(obj)
}

// Verify sprawdza podpis tresci kluczem z pola `key`.
func (c Confirmation) Verify(sig []byte) error {
	msg, err := c.Message()
	if err != nil {
		return err
	}
	pub, _ := base64.StdEncoding.DecodeString(c.Key)
	if !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
		return errors.New("podpis nie pasuje do klucza")
	}
	return nil
}
