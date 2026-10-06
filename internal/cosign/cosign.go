// Package cosign to format podpisu straznika `sigelith-cosign-v1`
// (PROTOCOL.md): tresc, kanoniczny JSON (podzbior JCS, RFC 8785 — ten sam co
// w checkpointach Sigelith), podpisywana wiadomosc i gotowy dokument.
package cosign

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"sigelith.org/cosigner/internal/logtree"
)

// V1 to wersja formatu i domena podpisu.
const V1 = "sigelith-cosign-v1"

// NameRE: nazwa straznika — stabilny identyfikator podmiotu, jak BEAT_KEY_OP.
var NameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// Since to poprzednia obserwacja straznika: rozmiar dziennika i chwila
// (wedlug zegara straznika) TUZ PRZED pobraniem wpisow.
type Since struct {
	Size uint64
	Time string
}

// Body to tresc podpisu (bez `sig`).
type Body struct {
	Log           string // nazwa dziennika (host), np. sigelith.org
	Cosigner      string // nazwa straznika, NameRE
	Key           string // klucz publiczny Ed25519 straznika, base64 (32 bajty)
	Size          uint64 // liczba lisci drzewa globalnego
	Root          string // korzen RFC 9162 przy Size, hex
	LastSeq       int64  // seq ostatniego wpisu w drzewie
	LastChainHash string // jego chain_hash — wiaze takze lancuch
	Time          string // zegar straznika PO pobraniu wpisow (canonical_utc)
	Since         *Since // poprzednia obserwacja albo nil (pierwsza)
}

func (b Body) object() map[string]any {
	obj := map[string]any{
		"v":               V1,
		"log":             b.Log,
		"cosigner":        b.Cosigner,
		"key":             b.Key,
		"size":            b.Size,
		"root":            b.Root,
		"last_seq":        b.LastSeq,
		"last_chain_hash": b.LastChainHash,
		"time":            b.Time,
		"since":           nil,
	}
	if b.Since != nil {
		obj["since"] = map[string]any{"size": b.Since.Size, "time": b.Since.Time}
	}
	return obj
}

// Validate sprawdza tresc przed podpisem — straznik nie podpisze bubla.
func (b Body) Validate() error {
	if b.Log == "" || !NameRE.MatchString(b.Cosigner) {
		return errors.New("log i cosigner sa wymagane (cosigner: [a-z0-9-], do 32 znakow)")
	}
	if raw, err := base64.StdEncoding.DecodeString(b.Key); err != nil || len(raw) != ed25519.PublicKeySize {
		return errors.New("key: klucz Ed25519 w base64")
	}
	if b.Size < 1 || b.Size >= 1<<53 || b.LastSeq < 1 || b.LastSeq >= 1<<53 {
		return errors.New("size i last_seq: liczby calkowite od 1")
	}
	if !logtree.IsHex64(b.Root) || !logtree.IsHex64(b.LastChainHash) {
		return errors.New("root i last_chain_hash: 64 znaki hex")
	}
	if _, err := logtree.ParseCanonical(b.Time); err != nil {
		return fmt.Errorf("time: %w", err)
	}
	if b.Since != nil {
		if b.Since.Size > b.Size {
			return errors.New("since.size wiekszy niz size — dziennik nie maleje")
		}
		if _, err := logtree.ParseCanonical(b.Since.Time); err != nil {
			return fmt.Errorf("since.time: %w", err)
		}
		if b.Since.Time > b.Time {
			return errors.New("since.time pozniejszy niz time")
		}
	}
	return nil
}

// Canonical to bajty JCS: klucze posortowane, bez spacji, bez ucieczek HTML,
// bez nowej linii na koncu. Dla tego podzbioru JSON (ASCII, liczby calkowite
// < 2^53) identyczne z json.dumps(sort_keys=True, separators=(',', ':')).
func Canonical(obj map[string]any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(obj); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// Message to podpisywane bajty: ASCII("sigelith-cosign-v1|") || JCS(tresc).
func (b Body) Message() ([]byte, error) {
	if err := b.Validate(); err != nil {
		return nil, err
	}
	body, err := Canonical(b.object())
	if err != nil {
		return nil, err
	}
	return append([]byte(V1+"|"), body...), nil
}

// Document to podpis gotowy do wyslania i archiwizacji: JCS(tresc + sig).
func (b Body) Document(sig []byte) ([]byte, error) {
	if len(sig) != ed25519.SignatureSize {
		return nil, errors.New("podpis Ed25519 ma 64 bajty")
	}
	obj := b.object()
	obj["sig"] = base64.StdEncoding.EncodeToString(sig)
	return Canonical(obj)
}

// Verify sprawdza podpis tresci kluczem z pola `key`.
func (b Body) Verify(sig []byte) error {
	msg, err := b.Message()
	if err != nil {
		return err
	}
	pub, _ := base64.StdEncoding.DecodeString(b.Key)
	if !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
		return errors.New("podpis nie pasuje do klucza")
	}
	return nil
}
