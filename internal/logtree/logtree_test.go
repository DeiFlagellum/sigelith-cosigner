package logtree

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

// Wektory z beattime apps/tsa/LOG.md, sekcja 10 (trzy wpisy z dziura w numeracji).
var vectors = []struct {
	seq     int64
	digest  string
	utc     string
	chain   string
	leafHex string
}{
	{1, "d426a3a1df05344e837b26a904177329f16f15aa4f9f934aa53d5c091a45cf0a", "2026-09-28T00:00:00.000000Z",
		"efd38a142ae66a266850702366269e31e7b1d70ca54eb266cad2f74a09b687ec",
		"0f57b2d73aadfbebd3812acfc7c8ecb1fec4d43f763ce42141dbb0bd248fb2fd"},
	{2, "cd53115f14511240719ef645d2cc250c84b6c8e3a3187951c9cba54fb3850436", "2026-09-28T09:06:03.926713Z",
		"c6e7db99f5c4fe429bd54203c35c0940ee415fa7d1aecb585cc40cd54815126a",
		"c13ae1ced21b7446b6cf87a8a54ce3b7f220461a8594bc2568c359b1e1f530d9"},
	{4, "3e6f0b0a97d1c5062629486dc6c632db1a5339c3d2bc49d3634d4bfa97b6a126", "2026-09-28T12:00:00.500000Z",
		"e424f49b574def86c8ac3d14ec22cb8da83fac8b8a1c2f243ed71303402f5af2",
		"fb28b9655ce639c2941c3f5857cf8cd3488e8ed9ce052f345e45243851d554fa"},
}

func TestLogVectors(t *testing.T) {
	prev := Genesis
	tree := &Tree{}
	for _, v := range vectors {
		ts, err := ParseCanonical(v.utc)
		if err != nil {
			t.Fatal(err)
		}
		if got := ChainHash(prev, v.digest, ts); got != v.chain {
			t.Fatalf("seq %d: chain_hash %s, oczekiwany %s", v.seq, got, v.chain)
		}
		leaf := EntryLeaf(v.seq, v.digest, ts)
		if got := hex.EncodeToString(leaf[:]); got != v.leafHex {
			t.Fatalf("seq %d: lisc %s, oczekiwany %s", v.seq, got, v.leafHex)
		}
		tree.Append(leaf)
		prev = v.chain
		root := tree.Root()
		switch tree.Size() {
		case 2:
			want(t, root, "f636e996038a2392ee6bcd3d282a7389d87d9ae1b7c7c369c25b27e5f2537cce")
		case 3:
			want(t, root, "bda0c891af7812124648447e1402ec9a9af54ced96e5600ac017f01512d5428d")
		}
	}
}

func want(t *testing.T, got [32]byte, hexWant string) {
	t.Helper()
	if hex.EncodeToString(got[:]) != hexWant {
		t.Fatalf("korzen %x, oczekiwany %s", got, hexWant)
	}
}

func TestChainUTCPitfall(t *testing.T) {
	zero := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
	if got := ChainUTC(zero); got != "2026-09-28T00:00:00+00:00" {
		t.Fatalf("zerowe mikrosekundy: %s", got)
	}
	half := time.Date(2026, 9, 28, 12, 0, 0, 500000000, time.UTC)
	if got := ChainUTC(half); got != "2026-09-28T12:00:00.500000+00:00" {
		t.Fatalf("ulamek: %s", got)
	}
}

func TestParseCanonicalIsStrict(t *testing.T) {
	for _, bad := range []string{"2026-09-28T00:00:00Z", "2026-09-28T00:00:00.000000+00:00",
		"2026-09-28 00:00:00.000000Z", "2026-09-28T00:00:00.0000000Z"} {
		if _, err := ParseCanonical(bad); err == nil {
			t.Errorf("przyjeto %q", bad)
		}
	}
}

// mth to definicja rekurencyjna z RFC 9162 2.1.1 — wzorzec dla krawedzi.
func mth(leaves [][32]byte) [32]byte {
	n := len(leaves)
	if n == 0 {
		return sha256.Sum256(nil)
	}
	if n == 1 {
		return leaves[0]
	}
	k := 1
	for k*2 < n {
		k *= 2
	}
	return node(mth(leaves[:k]), mth(leaves[k:]))
}

func TestTreeMatchesRFC9162AndRestores(t *testing.T) {
	var leaves [][32]byte
	tree := &Tree{}
	for i := 0; i < 70; i++ {
		leaf := sha256.Sum256([]byte{byte(i), byte(i >> 8)})
		leaves = append(leaves, leaf)
		tree.Append(leaf)
		if tree.Root() != mth(leaves) {
			t.Fatalf("rozmiar %d: korzen inny niz z definicji RFC 9162", i+1)
		}
		restored, err := Restore(tree.Size(), tree.Edges())
		if err != nil || restored.Root() != tree.Root() {
			t.Fatalf("rozmiar %d: odtworzenie krawedzi: %v", i+1, err)
		}
	}
	if _, err := Restore(5, []string{"00"}); err == nil {
		t.Fatal("przyjeto krawedz niezgodna z rozmiarem")
	}
}
