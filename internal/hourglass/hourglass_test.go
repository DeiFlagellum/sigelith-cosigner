package hourglass

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

// testdata/hourglass-vectors.json to kopia vectors/vectors.json z repozytorium
// sigelith-hourglass (commit 29fda98, sha256 ba792df9...2f35) - wektory
// implementacji referencyjnej. Ta implementacja ma dawac te same bajty.

type vectors struct {
	Chi           string    `json:"chi"`
	ClaimPermille [][3]int  `json:"claim_permille"`
	V1            v1Vectors `json:"v1"`
}

type v1Vectors struct {
	Trees []struct {
		N           int               `json:"n"`
		NodeCount   uint64            `json:"node_count"`
		InputLength int               `json:"input_length"`
		Root        string            `json:"root"`
		Labels      []json.RawMessage `json:"labels"`
	} `json:"trees"`
	Proofs []struct {
		N           int      `json:"n"`
		T           int      `json:"t"`
		Root        string   `json:"root"`
		Challenges  []uint64 `json:"challenges"`
		ProofSHA256 string   `json:"proof_sha256"`
		Proof       string   `json:"proof"`
	} `json:"proofs"`
	Chain struct {
		Genesis     json.RawMessage                 `json:"genesis"`
		GenesisRoot string                          `json:"genesis_root"`
		TestKey     struct{ Secret, Public string } `json:"test_key"`
		SigningMsg1 string                          `json:"signing_message_1"`
		Segments    []json.RawMessage               `json:"segments"`
		Proofs      []string                        `json:"proofs"`
		Unsigned1   json.RawMessage                 `json:"unsigned_1"`
	} `json:"chain"`
}

func load(t *testing.T) vectors {
	t.Helper()
	data, err := os.ReadFile("testdata/hourglass-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func obj(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	m, err := DecodeObject(raw)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// computeTree liczy wszystkie etykiety wprost z definicji grafu (§2-3).
func computeTree(n int, chi []byte) map[[2]uint64][32]byte {
	memo := map[[2]uint64][32]byte{}
	var lab func(depth int, bits uint64) [32]byte
	lab = func(depth int, bits uint64) [32]byte {
		key := [2]uint64{uint64(depth), bits}
		if v, ok := memo[key]; ok {
			return v
		}
		var parents [][]byte
		if depth == n {
			for i := 1; i <= n; i++ {
				if prefix := bits >> uint(n-i); prefix&1 == 1 {
					p := lab(i, prefix-1)
					parents = append(parents, p[:])
				}
			}
		} else {
			l, r := lab(depth+1, 2*bits), lab(depth+1, 2*bits+1)
			parents = [][]byte{l[:], r[:]}
		}
		v := Label(n, chi, depth, bits, parents...)
		memo[key] = v
		return v
	}
	lab(0, 0)
	return memo
}

func TestTreesV1(t *testing.T) {
	v := load(t)
	chi := unhex(t, v.Chi)
	if len(v.V1.Trees) == 0 {
		t.Fatal("brak wektorow drzew v1")
	}
	for _, tr := range v.V1.Trees {
		if InputLength(tr.N) != tr.InputLength || NodeCount(tr.N) != tr.NodeCount {
			t.Fatalf("n=%d: dlugosc wejscia %d/%d, wezly %d/%d", tr.N, InputLength(tr.N), tr.InputLength,
				NodeCount(tr.N), tr.NodeCount)
		}
		labels := computeTree(tr.N, chi)
		root := labels[[2]uint64{0, 0}]
		if hex.EncodeToString(root[:]) != tr.Root {
			t.Fatalf("n=%d: korzen %x, wektor %s", tr.N, root, tr.Root)
		}
		for _, raw := range tr.Labels {
			var item [3]any
			if err := json.Unmarshal(raw, &item); err != nil {
				t.Fatal(err)
			}
			d, b := uint64(item[0].(float64)), uint64(item[1].(float64))
			got := labels[[2]uint64{d, b}]
			if hex.EncodeToString(got[:]) != item[2].(string) {
				t.Fatalf("n=%d: etykieta (%d, %d) inna niz w wektorze", tr.N, d, b)
			}
		}
	}
}

func TestProofsV1(t *testing.T) {
	v := load(t)
	chi := unhex(t, v.Chi)
	for _, p := range v.V1.Proofs {
		root, proof := unhex(t, p.Root), unhex(t, p.Proof)
		if got := Challenges(p.N, chi, root, p.T); !reflect.DeepEqual(got, p.Challenges) {
			t.Fatalf("n=%d: kontrole %v, wektor %v", p.N, got, p.Challenges)
		}
		if sum := sha256.Sum256(proof); hex.EncodeToString(sum[:]) != p.ProofSHA256 {
			t.Fatalf("n=%d: skrot dowodu", p.N)
		}
		if !VerifyProof(p.N, p.T, chi, root, proof) {
			t.Fatalf("n=%d: poprawny dowod odrzucony", p.N)
		}
		// przedrostek z pierwszymi kontrolami tez jest dowodem (§10.1)
		if !VerifyProof(p.N, 1, chi, root, proof[:p.N*LabelSize]) {
			t.Fatalf("n=%d: przedrostek odrzucony", p.N)
		}
		for _, at := range []int{0, len(proof) / 2, len(proof) - 1} {
			bad := append([]byte(nil), proof...)
			bad[at] ^= 1
			if VerifyProof(p.N, p.T, chi, root, bad) {
				t.Fatalf("n=%d: przyjety dowod z bledem w bajcie %d", p.N, at)
			}
		}
		if VerifyProof(p.N, p.T, chi, root, proof[:len(proof)-1]) {
			t.Fatalf("n=%d: przyjety za krotki dowod", p.N)
		}
	}
}

func TestClaimPermille(t *testing.T) {
	v := load(t)
	if len(v.ClaimPermille) == 0 {
		t.Fatal("brak wektorow claim_permille")
	}
	for _, c := range v.ClaimPermille {
		if got := ClaimPermille(c[0], c[1]); got != c[2] {
			t.Fatalf("claim_permille(%d, %d) = %d, wektor %d", c[0], c[1], got, c[2])
		}
	}
}

func TestChainV1(t *testing.T) {
	v := load(t)
	c := v.V1.Chain
	g := obj(t, c.Genesis)
	phi, err := GenesisRoot(g)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(phi[:]) != c.GenesisRoot {
		t.Fatalf("phi_0 %x, wektor %s", phi, c.GenesisRoot)
	}
	keys := []string{c.TestKey.Public}
	prev, prevUTC := phi[:], g["utc"].(string)
	for i, raw := range c.Segments {
		rec := obj(t, raw)
		seg, err := CheckSegment(rec, unhex(t, c.Proofs[i]), prev, prevUTC, Options{Signed: true, Keys: keys})
		if err != nil {
			t.Fatalf("odcinek %d: %v", i+1, err)
		}
		if seg.J != int64(i+1) || seg.Key != c.TestKey.Public {
			t.Fatalf("odcinek %d: %+v", i+1, seg)
		}
		prev, prevUTC = unhex(t, seg.Root), seg.UTCEnd
	}
	msg, err := SigningMessage(obj(t, c.Segments[0]))
	if err != nil || string(msg) != c.SigningMsg1 {
		t.Fatalf("wiadomosc podpisu inna niz w wektorze: %v", err)
	}
}

// Rekord prosto z provera: sprawdzenie przed podpisem i podpis tym samym kluczem daja
// dokladnie rekord z wektora (Ed25519 jest deterministyczny).
func TestSignUnsignedV1(t *testing.T) {
	v := load(t)
	c := v.V1.Chain
	phi := unhex(t, c.GenesisRoot)
	g := obj(t, c.Genesis)
	rec := obj(t, c.Unsigned1)
	if _, err := CheckSegment(rec, unhex(t, c.Proofs[0]), phi, g["utc"].(string), Options{}); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckSegment(rec, unhex(t, c.Proofs[0]), phi, g["utc"].(string), Options{Signed: true}); err == nil {
		t.Fatal("rekord bez podpisu przyjety jako podpisany")
	}
	priv := ed25519.NewKeyFromSeed(unhex(t, c.TestKey.Secret))
	rec["key"] = base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	msg, err := SigningMessage(rec)
	if err != nil {
		t.Fatal(err)
	}
	rec["sig"] = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg))
	got, _ := Canonical(rec)
	want, _ := Canonical(obj(t, c.Segments[0]))
	if string(got) != string(want) {
		t.Fatalf("podpisany rekord inny niz w wektorze:\n%s\n%s", got, want)
	}
}

func TestRejects(t *testing.T) {
	v := load(t)
	c := v.V1.Chain
	phi := unhex(t, c.GenesisRoot)
	start := obj(t, c.Genesis)["utc"].(string)
	proof := unhex(t, c.Proofs[0])
	keys := []string{c.TestKey.Public}
	other := base64.StdEncoding.EncodeToString(ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey))
	cases := []struct {
		name   string
		edit   func(m map[string]any)
		proof  []byte
		prev   []byte
		keys   []string
		expect string
	}{
		{"pole pokrycia", func(m map[string]any) { m["coverage_permille"] = json.Number("969") }, nil, nil, nil, "coverage_permille"},
		{"klucz spoza historii", nil, nil, nil, []string{other}, "spoza historii"},
		{"brak kluczy", nil, nil, nil, []string{}, "spoza historii"},
		{"zly poprzedni korzen", nil, nil, make([]byte, 32), nil, "prev_root"},
		{"dowod z bledem", nil, append(append([]byte{}, proof[:len(proof)-1]...), proof[len(proof)-1]^1), nil, nil, "skrot pliku dowodu"},
		{"dowod za krotki", nil, proof[:len(proof)-32], nil, nil, "bajtow zamiast"},
		{"liczba z ulamkiem", func(m map[string]any) { m["k_assumed"] = json.Number("1.0") }, nil, nil, nil, "k_assumed"},
		{"dodatkowe pole", func(m map[string]any) { m["x"] = "y" }, nil, nil, nil, "zly zestaw pol"},
		{"podpis z bledem", func(m map[string]any) {
			s := m["sig"].(string)
			m["sig"] = "A" + s[1:]
		}, nil, nil, nil, "podpis NIE pasuje"},
	}
	for _, tc := range cases {
		rec := obj(t, c.Segments[0])
		if tc.edit != nil {
			tc.edit(rec)
		}
		p, prev, k := proof, phi, keys
		if tc.proof != nil {
			p = tc.proof
		}
		if tc.prev != nil {
			prev = tc.prev
		}
		if tc.keys != nil {
			k = tc.keys
		}
		_, err := CheckSegment(rec, p, prev, start, Options{Signed: true, Keys: k})
		if err == nil || !strings.Contains(err.Error(), tc.expect) {
			t.Fatalf("%s: oczekiwany blad %q, jest %v", tc.name, tc.expect, err)
		}
	}
}

func TestCanonical(t *testing.T) {
	in := []byte(`{"b":[1,-2,{"z":null,"a":true}],"a":"x\"y\\ z ą  "}`)
	v, err := Decode(in)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Canonical(v)
	if err != nil {
		t.Fatal(err)
	}
	want := "{\"a\":\"x\\\"y\\\\ z ą  \",\"b\":[1,-2,{\"a\":true,\"z\":null}]}"
	if string(got) != want {
		t.Fatalf("JCS:\n%s\n%s", got, want)
	}
	for _, bad := range []string{`{"a":1.5}`, `{"a":1e3}`, `{"a":9007199254740992}`, `{"a":"x\ty"}`, `{"ą":1}`} {
		v, err := Decode([]byte(bad))
		if err == nil {
			_, err = Canonical(v)
		}
		if err == nil {
			t.Fatalf("przyjete: %s", bad)
		}
	}
	if _, err := Decode([]byte(`{"a":1} {}`)); err == nil {
		t.Fatal("przyjete dane po wartosci")
	}
}

// Prawdziwe dane (pobrane z /api/hourglass/<zegar>/...): HOURGLASS_DIR=<katalog z genesis.json
// i segments/<j>.json + .proof>, HOURGLASS_KEY=<klucz operatora, base64>. Bez zmiennych - pominiety.
func TestRealData(t *testing.T) {
	dir, key := os.Getenv("HOURGLASS_DIR"), os.Getenv("HOURGLASS_KEY")
	if dir == "" || key == "" {
		t.Skip("HOURGLASS_DIR i HOURGLASS_KEY nieustawione")
	}
	raw, err := os.ReadFile(dir + "/genesis.json")
	if err != nil {
		t.Fatal(err)
	}
	g := obj(t, raw)
	phi, err := GenesisRoot(g)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("phi_0 %x", phi)
	prev, prevUTC := phi[:], g["utc"].(string)
	for j := 1; ; j++ {
		name := fmt.Sprintf("%s/segments/%06d", dir, j)
		raw, err := os.ReadFile(name + ".json")
		if os.IsNotExist(err) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		proof, err := os.ReadFile(name + ".proof")
		if err != nil {
			t.Fatal(err)
		}
		rec := obj(t, raw)
		if canon, _ := Canonical(rec); string(canon) != string(raw) {
			t.Fatalf("odcinek %d: plik nie jest kanonicznym JSON", j)
		}
		seg, err := CheckSegment(rec, proof, prev, prevUTC, Options{Signed: true, Keys: []string{key}})
		if err != nil {
			t.Fatalf("odcinek %d: %v", j, err)
		}
		t.Logf("odcinek %d OK: root %s, koniec %s", j, seg.Root, seg.UTCEnd)
		prev, prevUTC = unhex(t, seg.Root), seg.UTCEnd
	}
}
