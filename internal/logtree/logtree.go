// Package logtree odtwarza dziennik Sigelith bajt w bajt tak jak serwer
// (beattime: apps/tsa/merkle.py, specyfikacja apps/tsa/LOG.md, sekcje 2 i 4):
// ogniwa lancucha, liscie drzewa globalnego i korzen drzewa RFC 9162.
//
// Straznik NIE bierze od serwera ani korzenia, ani dowodow spojnosci: liczy
// drzewo sam z publicznych wpisow. Trzyma przy tym tylko „krawedz" drzewa
// (najwyzej log2 N hashy), wiec pamiec nie rosnie razem z dziennikiem.
package logtree

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"regexp"
	"strconv"
	"time"
)

// EntryV1 to domena liscia drzewa globalnego (LOG.md 4).
const EntryV1 = "beattime-entry-v1"

// Genesis to prev_chain pierwszego wpisu.
const Genesis = "0000000000000000000000000000000000000000000000000000000000000000"

var (
	canonicalRE = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$`)
	hex64RE     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// CanonicalUTC to czas w nowych formatach: zawsze szesc cyfr ulamka i Z.
func CanonicalUTC(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000000Z")
}

// ParseCanonical przyjmuje WYLACZNIE postac z CanonicalUTC.
func ParseCanonical(s string) (time.Time, error) {
	if !canonicalRE.MatchString(s) {
		return time.Time{}, fmt.Errorf("czas %q nie ma postaci YYYY-MM-DDTHH:MM:SS.ffffffZ", s)
	}
	return time.Parse("2006-01-02T15:04:05.000000Z", s)
}

// ChainUTC odtwarza HISTORYCZNA postac czasu w ogniwach: Pythonowe
// datetime.isoformat() dla UTC, czyli ...SS.ffffff+00:00, ale BEZ ulamka,
// gdy mikrosekundy wynosza dokladnie 0 (LOG.md 2, „pulapka chain_utc").
func ChainUTC(t time.Time) string {
	t = t.UTC()
	if t.Nanosecond()/1000 == 0 {
		return t.Format("2006-01-02T15:04:05") + "+00:00"
	}
	return t.Format("2006-01-02T15:04:05.000000") + "+00:00"
}

// ChainHash = hex(SHA-256(prev_chain || digest || chain_utc(utc))).
func ChainHash(prev, digest string, t time.Time) string {
	sum := sha256.Sum256([]byte(prev + digest + ChainUTC(t)))
	return hex.EncodeToString(sum[:])
}

// IsHex64 sprawdza 64 znaki hex malymi literami.
func IsHex64(s string) bool { return hex64RE.MatchString(s) }

// EntryLeaf = SHA-256(0x00 || ASCII("beattime-entry-v1|seq|digest|canonical_utc")).
func EntryLeaf(seq int64, digest string, t time.Time) [32]byte {
	entry := EntryV1 + "|" + strconv.FormatInt(seq, 10) + "|" + digest + "|" + CanonicalUTC(t)
	return sha256.Sum256(append([]byte{0x00}, entry...))
}

func node(left, right [32]byte) [32]byte {
	buf := make([]byte, 0, 65)
	buf = append(buf, 0x01)
	buf = append(buf, left[:]...)
	buf = append(buf, right[:]...)
	return sha256.Sum256(buf)
}

// Tree to drzewo RFC 9162 trzymane jako krawedz: korzenie pelnych poddrzew
// odpowiadajace jedynkom w zapisie dwojkowym rozmiaru, od najwiekszego.
type Tree struct {
	size  uint64
	edges [][32]byte
}

// Size to liczba lisci.
func (t *Tree) Size() uint64 { return t.size }

// Append dokleja lisc na koncu drzewa.
func (t *Tree) Append(leaf [32]byte) {
	t.edges = append(t.edges, leaf)
	t.size++
	// Kazde zero na koncu nowego rozmiaru to scalenie dwoch rownych poddrzew.
	for n := t.size; n&1 == 0; n >>= 1 {
		last := len(t.edges) - 1
		t.edges = append(t.edges[:last-1], node(t.edges[last-1], t.edges[last]))
	}
}

// Root to MTH z RFC 9162 2.1.1: skladanie krawedzi od prawej. Dla pustego
// drzewa — SHA-256 pustego napisu, jak w RFC (straznik go nie podpisuje).
func (t *Tree) Root() [32]byte {
	if t.size == 0 {
		return sha256.Sum256(nil)
	}
	root := t.edges[len(t.edges)-1]
	for i := len(t.edges) - 2; i >= 0; i-- {
		root = node(t.edges[i], root)
	}
	return root
}

// Edges to krawedz w hex — do zapisu stanu.
func (t *Tree) Edges() []string {
	out := make([]string, len(t.edges))
	for i, e := range t.edges {
		out[i] = hex.EncodeToString(e[:])
	}
	return out
}

// Restore odtwarza drzewo z rozmiaru i krawedzi zapisanych przez Edges.
func Restore(size uint64, edges []string) (*Tree, error) {
	if bits.OnesCount64(size) != len(edges) {
		return nil, errors.New("krawedz drzewa nie pasuje do rozmiaru")
	}
	t := &Tree{size: size, edges: make([][32]byte, len(edges))}
	for i, s := range edges {
		if !IsHex64(s) {
			return nil, fmt.Errorf("krawedz %d: to nie jest hash", i)
		}
		raw, _ := hex.DecodeString(s)
		copy(t.edges[i][:], raw)
	}
	return t, nil
}
