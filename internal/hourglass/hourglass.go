// Package hourglass sprawdza odcinki Klepsydry Sigelith v1 (Sigelith Hourglass,
// repozytorium sigelith-hourglass, SPEC.md): dowod pracy sekwencyjnej
// Cohena-Pietrzaka na SHA-256, ziarno z poprzedniego korzenia i wejsc, pola
// rekordu i podpis operatora zegara (Ed25519).
//
// To niezalezna implementacja w Go. Ma dawac dokladnie te same bajty i te same
// decyzje co implementacja referencyjna (reference/hourglass_ref.py); sprawdza
// ja test na jej wektorach (testdata/hourglass-vectors.json). Obsluguje tylko
// v1 (faza 0 zakonczyla sie 23.11.2026) i tylko pelne dowody.
package hourglass

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"
)

// Identyfikatory v1 (SPEC.md §1, §8).
const (
	Tag           = "sigelith-hourglass-v1"
	GenesisFormat = "sigelith-hourglass-genesis-v1"
	SegmentFormat = "sigelith-hourglass-segment-v1"
	SigDomain     = "sigelith-hourglass-segment-v1|"

	LabelSize = 32
	MaxN      = 48
	MaxT      = 1024
	MaxLambda = 256
	maxInt    = int64(1) << 53
)

var (
	utcRE      = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$`)
	hex64RE    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	proofRE    = regexp.MustCompile(`^[0-9]{6,}\.proof$`)
	operatorRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?$`)
)

// Error to dane niezgodne ze specyfikacja.
type Error struct{ Msg string }

func (e *Error) Error() string { return e.Msg }

func fail(format string, args ...any) error { return &Error{Msg: fmt.Sprintf(format, args...)} }

// --- §7 Kanoniczny JSON (podzbior JCS, RFC 8785, ten sam co checkpointy Sigelith) ---

// Decode czyta dokladnie jedna wartosc JSON; liczby zostaja dokladne (json.Number).
func Decode(data []byte) (any, error) {
	if !utf8.Valid(data) {
		return nil, fail("JSON: niepoprawne UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fail("JSON: %v", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fail("JSON: dane po wartosci")
	}
	return v, nil
}

// DecodeObject to Decode dla obiektu JSON.
func DecodeObject(data []byte) (map[string]any, error) {
	v, err := Decode(data)
	if err != nil {
		return nil, err
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, fail("JSON: oczekiwany obiekt")
	}
	return obj, nil
}

// Canonical to bajty JCS: klucze ASCII posortowane, bez spacji, liczby calkowite
// ponizej 2^53, napisy bez znakow sterujacych - jak canonical_json w referencji.
func Canonical(v any) ([]byte, error) {
	var b bytes.Buffer
	if err := writeJCS(&b, v, "$"); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func writeString(b *bytes.Buffer, s, path string) error {
	for _, r := range s {
		if r < 0x20 {
			return fail("%s: znak sterujacy w napisie", path)
		}
	}
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		if c := s[i]; c == '"' || c == '\\' {
			b.WriteByte('\\')
		}
		b.WriteByte(s[i])
	}
	b.WriteByte('"')
	return nil
}

func writeInt(b *bytes.Buffer, i int64, path string) error {
	if i >= maxInt || i <= -maxInt {
		return fail("%s: liczba poza zakresem 2**53", path)
	}
	b.WriteString(strconv.FormatInt(i, 10))
	return nil
}

func writeJCS(b *bytes.Buffer, v any, path string) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(x))
	case json.Number:
		i, err := strconv.ParseInt(string(x), 10, 64)
		if err != nil {
			return fail("%s: dozwolone tylko liczby calkowite ponizej 2**53", path)
		}
		return writeInt(b, i, path)
	case int:
		return writeInt(b, int64(x), path)
	case int64:
		return writeInt(b, x, path)
	case string:
		return writeString(b, x, path)
	case []any:
		b.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeJCS(b, item, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			for i := 0; i < len(k); i++ {
				if k[i] >= 0x80 {
					return fail("%s: klucz musi byc napisem ASCII", path)
				}
			}
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeString(b, k, path+"."+k); err != nil {
				return err
			}
			b.WriteByte(':')
			if err := writeJCS(b, x[k], path+"."+k); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fail("%s: niedozwolony typ %T", path, v)
	}
	return nil
}

// --- Pola ---

func intOf(v any, name string, lo int64) (int64, error) {
	n, ok := v.(json.Number)
	if !ok {
		if i, isInt := v.(int64); isInt {
			n, ok = json.Number(strconv.FormatInt(i, 10)), true
		}
	}
	if ok {
		if i, err := strconv.ParseInt(string(n), 10, 64); err == nil && i >= lo && i < maxInt {
			return i, nil
		}
	}
	return 0, fail("%s: oczekiwana liczba calkowita >= %d", name, lo)
}

func strOf(v any, re *regexp.Regexp, name, what string) (string, error) {
	s, ok := v.(string)
	if !ok || !re.MatchString(s) {
		return "", fail("%s: oczekiwane %s", name, what)
	}
	return s, nil
}

func checkUTC(v any, name string) (string, error) {
	return strOf(v, utcRE, name, "YYYY-MM-DDTHH:MM:SS.ffffffZ")
}

func checkHex64(v any, name string) (string, error) {
	return strOf(v, hex64RE, name, "64 znaki hex (male litery)")
}

func hasKeys(m map[string]any, keys ...string) bool {
	if len(m) != len(keys) {
		return false
	}
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			return false
		}
	}
	return true
}

func objOf(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

// UTCMicros to mikrosekundy od 1970 dla czasu YYYY-MM-DDTHH:MM:SS.ffffffZ.
func UTCMicros(s string) (int64, error) {
	if !utcRE.MatchString(s) {
		return 0, fail("utc: oczekiwane YYYY-MM-DDTHH:MM:SS.ffffffZ")
	}
	t, err := time.Parse("2006-01-02T15:04:05.000000Z", s)
	if err != nil {
		return 0, fail("utc: %v", err)
	}
	return t.UnixMicro(), nil
}

// CheckParams: n 1..48, t 1..1024, lambda 1..256.
func CheckParams(n, t, lam int64) error {
	for _, p := range []struct {
		name      string
		v, lo, hi int64
	}{{"n", n, 1, MaxN}, {"t", t, 1, MaxT}, {"lambda", lam, 1, MaxLambda}} {
		if p.v < p.lo || p.v > p.hi {
			return fail("%s poza zakresem %d..%d", p.name, p.lo, p.hi)
		}
	}
	return nil
}

// --- §2-3 Graf odcinka i etykieta wezla ---

func sep(kind string) []byte { return []byte(Tag + "|" + kind + "|") }

func sha(parts ...[]byte) [32]byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// NodeCount: N = 2^(n+1) - 1 wezlow.
func NodeCount(n int) uint64 { return (uint64(1) << uint(n+1)) - 1 }

func maxParents(n int) int {
	if n > 2 {
		return n
	}
	return 2
}

// labeler liczy etykiety wezlow odcinka o glebokosci n i ziarnie chi: wejscie
// SHA-256 ma zawsze ta sama dlugosc (zera dopelniaja je NA KONCU, §3).
type labeler struct {
	n   int
	buf []byte
	pos int // poczatek pola wezla
}

func newLabeler(n int, chi []byte) *labeler {
	pre := append(sep("node"), chi...)
	buf := make([]byte, len(pre)+9+LabelSize*maxParents(n))
	copy(buf, pre)
	return &labeler{n: n, buf: buf, pos: len(pre)}
}

// InputLength: stala dlugosc wejscia SHA-256 dla wezla odcinka o glebokosci n.
func InputLength(n int) int { return len(sep("node")) + LabelSize + 9 + LabelSize*maxParents(n) }

func (l *labeler) label(depth int, bits uint64, parents ...[]byte) [32]byte {
	l.buf[l.pos] = byte(depth)
	binary.BigEndian.PutUint64(l.buf[l.pos+1:], bits)
	off := l.pos + 9
	for _, p := range parents {
		copy(l.buf[off:], p)
		off += LabelSize
	}
	clear(l.buf[off:])
	return sha256.Sum256(l.buf)
}

// Label to etykieta jednego wezla (do testow na wektorach drzew).
func Label(n int, chi []byte, depth int, bits uint64, parents ...[]byte) [32]byte {
	return newLabeler(n, chi).label(depth, bits, parents...)
}

// --- §5 Kontrole z Fiata-Shamira i sprawdzenie dowodu ---

// Challenges: gamma_i = pierwsze n bitow SHA-256(sep|challenge| || chi || phi || BE32(i)).
func Challenges(n int, chi, root []byte, t int) []uint64 {
	out := make([]uint64, t)
	var idx [4]byte
	for i := 1; i <= t; i++ {
		binary.BigEndian.PutUint32(idx[:], uint32(i))
		h := sha(sep("challenge"), chi, root, idx[:])
		out[i-1] = binary.BigEndian.Uint64(h[:8]) >> uint(64-n)
	}
	return out
}

// VerifyProof sprawdza dowod odcinka: t kontroli po n etykiet rodzenstwa (od liscia w gore).
func VerifyProof(n, t int, chi, root, proof []byte) bool {
	if n < 1 || n > MaxN || t < 1 || t > MaxT || len(chi) != LabelSize || len(root) != LabelSize ||
		len(proof) != t*n*LabelSize {
		return false
	}
	l := newLabeler(n, chi)
	parents := make([][]byte, 0, n)
	for idx, u := range Challenges(n, chi, root, t) {
		base := idx * n * LabelSize
		sib := func(k int) []byte { return proof[base+LabelSize*k : base+LabelSize*(k+1)] }
		// rodzice liscia: lewe rodzenstwo na sciezce, od korzenia w dol; sib(k) lezy na glebokosci n - k
		parents = parents[:0]
		for i := 1; i <= n; i++ {
			if (u>>uint(n-i))&1 == 1 {
				parents = append(parents, sib(n-i))
			}
		}
		cur := l.label(n, u, parents...)
		for d := n; d >= 1; d-- {
			prefix := u >> uint(n-d)
			s := sib(n - d)
			if prefix&1 == 1 {
				cur = l.label(d-1, prefix>>1, s, cur[:])
			} else {
				cur = l.label(d-1, prefix>>1, cur[:], s)
			}
		}
		if !bytes.Equal(cur[:], root) {
			return false
		}
	}
	return true
}

// --- §6 Czesc krokow gwarantowana przez kontrole ---

var claimCache sync.Map

// ClaimPermille: najwieksze p (promile), dla ktorego (p/1000)^t <= 2^-lambda.
func ClaimPermille(t, lam int) int {
	key := [2]int{t, lam}
	if v, ok := claimCache.Load(key); ok {
		return v.(int)
	}
	limit := new(big.Int).Exp(big.NewInt(1000), big.NewInt(int64(t)), nil)
	lo, hi := 0, 1000
	for lo < hi {
		mid := (lo + hi + 1) / 2
		v := new(big.Int).Exp(big.NewInt(int64(mid)), big.NewInt(int64(t)), nil)
		v.Lsh(v, uint(lam))
		if v.Cmp(limit) <= 0 {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	claimCache.Store(key, lo)
	return lo
}

// CoveragePermille: N / (najwyzsza predkosc * czas zegarowy) w promilach (informacja).
func CoveragePermille(n int, maxSpeed int64, utcStart, utcEnd string) (int64, error) {
	a, err := UTCMicros(utcStart)
	if err != nil {
		return 0, err
	}
	b, err := UTCMicros(utcEnd)
	if err != nil {
		return 0, err
	}
	wall := b - a
	if wall <= 0 || maxSpeed <= 0 {
		return 0, fail("pokrycie: zly czas albo predkosc")
	}
	num := new(big.Int).Mul(big.NewInt(1000*1_000_000), new(big.Int).SetUint64(NodeCount(n)))
	den := new(big.Int).Mul(big.NewInt(maxSpeed), big.NewInt(wall))
	return new(big.Int).Quo(num, den).Int64(), nil
}

// --- §7 Genesis, wejscia i ziarno ---

func checkBTC(v any) error {
	m := objOf(v)
	if m == nil || !hasKeys(m, "height", "hash") {
		return fail("btc: pola height i hash")
	}
	if _, err := intOf(m["height"], "btc.height", 0); err != nil {
		return err
	}
	_, err := checkHex64(m["hash"], "btc.hash")
	return err
}

func checkCheckpoint(v any) error {
	m := objOf(v)
	if m == nil || !hasKeys(m, "n", "sha256") {
		return fail("checkpoint: pola n i sha256")
	}
	if _, err := intOf(m["n"], "checkpoint.n", 1); err != nil {
		return err
	}
	_, err := checkHex64(m["sha256"], "checkpoint.sha256")
	return err
}

// CheckOperator: 1-64 znakow a-z 0-9 . -, na brzegach litera albo cyfra.
func CheckOperator(v any) error {
	if _, err := strOf(v, operatorRE, "operator", "1-64 znakow a-z 0-9 . -"); err != nil {
		return err
	}
	return nil
}

func params(m map[string]any) (n, t, lam int64, err error) {
	if n, err = intOf(m["n"], "n", 1); err != nil {
		return
	}
	if t, err = intOf(m["t"], "t", 1); err != nil {
		return
	}
	if lam, err = intOf(m["lambda"], "lambda", 1); err != nil {
		return
	}
	err = CheckParams(n, t, lam)
	return
}

// CheckGenesis sprawdza genesis v1 (§7).
func CheckGenesis(g map[string]any) error {
	if !hasKeys(g, "v", "hash", "operator", "n", "t", "lambda", "checkpoint", "btc", "utc", "k_assumed",
		"s_ref_nodes_per_s") {
		return fail("genesis: zly zestaw pol")
	}
	if g["v"] != GenesisFormat {
		return fail("genesis: v musi byc %s", GenesisFormat)
	}
	if g["hash"] != "sha-256" {
		return fail("genesis: hash musi byc sha-256")
	}
	if _, _, _, err := params(g); err != nil {
		return err
	}
	if err := checkCheckpoint(g["checkpoint"]); err != nil {
		return err
	}
	if err := checkBTC(g["btc"]); err != nil {
		return err
	}
	if _, err := checkUTC(g["utc"], "genesis.utc"); err != nil {
		return err
	}
	if _, err := intOf(g["k_assumed"], "k_assumed", 1); err != nil {
		return err
	}
	if err := CheckOperator(g["operator"]); err != nil {
		return err
	}
	if _, err := intOf(g["s_ref_nodes_per_s"], "s_ref_nodes_per_s", 1); err != nil {
		return err
	}
	_, err := Canonical(g)
	return err
}

// GenesisRoot: phi_0 = SHA-256(sep|genesis| || JCS(genesis)).
func GenesisRoot(g map[string]any) ([32]byte, error) {
	if err := CheckGenesis(g); err != nil {
		return [32]byte{}, err
	}
	data, _ := Canonical(g)
	return sha(sep("genesis"), data), nil
}

func checkInputs(v any) (map[string]any, error) {
	m := objOf(v)
	if m == nil || !hasKeys(m, "btc", "checkpoint", "utc") {
		return nil, fail("inputs: pola btc, checkpoint, utc")
	}
	if err := checkBTC(m["btc"]); err != nil {
		return nil, err
	}
	if err := checkCheckpoint(m["checkpoint"]); err != nil {
		return nil, err
	}
	if _, err := checkUTC(m["utc"], "inputs.utc"); err != nil {
		return nil, err
	}
	return m, nil
}

// Seed: chi_j = SHA-256(sep|seed| || BE64(j) || phi_{j-1} || SHA-256(JCS(inputs))).
func Seed(j int64, prevRoot []byte, inputs any) ([32]byte, error) {
	m, err := checkInputs(inputs)
	if err != nil {
		return [32]byte{}, err
	}
	if j < 1 || len(prevRoot) != LabelSize {
		return [32]byte{}, fail("ziarno: j >= 1 i poprzedni korzen 32 bajty")
	}
	data, err := Canonical(m)
	if err != nil {
		return [32]byte{}, err
	}
	x := sha256.Sum256(data)
	var be [8]byte
	binary.BigEndian.PutUint64(be[:], uint64(j))
	return sha(sep("seed"), be[:], prevRoot, x[:]), nil
}

// --- §8 Podpis rekordu v1 ---

// B64Field: kanoniczne base64 (RFC 4648, z dopelnieniem) dokladnie size bajtow.
func B64Field(v any, size int, name string) ([]byte, error) {
	s, ok := v.(string)
	if !ok {
		return nil, fail("%s: oczekiwane base64", name)
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || len(raw) != size || base64.StdEncoding.EncodeToString(raw) != s {
		return nil, fail("%s: oczekiwane kanoniczne base64 %d bajtow", name, size)
	}
	return raw, nil
}

// SigningMessage: `sigelith-hourglass-segment-v1|` || JCS(rekord bez sig).
func SigningMessage(rec map[string]any) ([]byte, error) {
	body := make(map[string]any, len(rec))
	for k, v := range rec {
		if k != "sig" {
			body[k] = v
		}
	}
	data, err := Canonical(body)
	if err != nil {
		return nil, err
	}
	return append([]byte(SigDomain), data...), nil
}

// --- §8-9 Rekord odcinka ---

var unsignedKeys = []string{"v", "j", "n", "t", "lambda", "prev_root", "inputs", "seed", "root", "proof",
	"utc_end", "gaps", "speed", "ptb_offset_us", "k_assumed", "claim_permille", "coverage_permille",
	"s_ref_nodes_per_s"}

// Options mowi, co jeszcze sprawdzic w rekordzie.
type Options struct {
	// Signed: rekord opublikowany (z key i sig); false = prosto z provera, przed podpisem.
	Signed bool
	// Keys: historia kluczy operatora (base64); dla Signed podpis musi pasowac do jednego z nich.
	// Pusta lista przy Signed = blad - straznik zawsze sprawdza podpis.
	Keys []string
}

// Segment to odczytane pola sprawdzonego rekordu.
type Segment struct {
	J      int64
	Root   string
	UTCEnd string
	Key    string // pusty dla rekordu bez podpisu
}

// CheckSegment sprawdza rekord odcinka v1 wzgledem poprzedniego korzenia i czasu, z pelnym
// dowodem (§8-9) - te same warunki i w tej samej kolejnosci co check_segment w referencji.
func CheckSegment(rec map[string]any, proof, prevRoot []byte, prevUTC string, opt Options) (Segment, error) {
	keys := unsignedKeys
	if opt.Signed {
		keys = append(append([]string{}, unsignedKeys...), "key", "sig")
	}
	if !hasKeys(rec, keys...) {
		return Segment{}, fail("rekord: zly zestaw pol")
	}
	if rec["v"] != SegmentFormat {
		return Segment{}, fail("rekord: v musi byc %s", SegmentFormat)
	}
	j, err := intOf(rec["j"], "j", 1)
	if err != nil {
		return Segment{}, err
	}
	n64, t64, lam, err := params(rec)
	if err != nil {
		return Segment{}, err
	}
	n, t := int(n64), int(t64)
	if _, err := Canonical(rec); err != nil {
		return Segment{}, err
	}
	prevHex, err := checkHex64(rec["prev_root"], "prev_root")
	if err != nil {
		return Segment{}, err
	}
	if prevHex != hex.EncodeToString(prevRoot) {
		return Segment{}, fail("odcinek %d: prev_root nie pasuje do poprzedniego korzenia", j)
	}
	inputs, err := checkInputs(rec["inputs"])
	if err != nil {
		return Segment{}, err
	}
	start := inputs["utc"].(string)
	if start < prevUTC {
		return Segment{}, fail("odcinek %d: inputs.utc wczesniejsze niz koniec poprzedniego", j)
	}
	end, err := checkUTC(rec["utc_end"], "utc_end")
	if err != nil {
		return Segment{}, err
	}
	if !(end > start) {
		return Segment{}, fail("odcinek %d: utc_end nie po starcie", j)
	}
	chi, err := Seed(j, prevRoot, inputs)
	if err != nil {
		return Segment{}, err
	}
	seedHex, err := checkHex64(rec["seed"], "seed")
	if err != nil {
		return Segment{}, err
	}
	if seedHex != hex.EncodeToString(chi[:]) {
		return Segment{}, fail("odcinek %d: ziarno nie wynika z prev_root i inputs", j)
	}
	rootHex, err := checkHex64(rec["root"], "root")
	if err != nil {
		return Segment{}, err
	}
	pf := objOf(rec["proof"])
	if pf == nil || !hasKeys(pf, "file", "sha256") {
		return Segment{}, fail("proof: pola file i sha256")
	}
	if _, err := strOf(pf["file"], proofRE, "proof.file", "<j>.proof"); err != nil {
		return Segment{}, err
	}
	proofSHA, err := checkHex64(pf["sha256"], "proof.sha256")
	if err != nil {
		return Segment{}, err
	}
	if len(proof) != t*n*LabelSize {
		return Segment{}, fail("odcinek %d: dowod ma %d bajtow zamiast %d", j, len(proof), t*n*LabelSize)
	}
	if sum := sha256.Sum256(proof); hex.EncodeToString(sum[:]) != proofSHA {
		return Segment{}, fail("odcinek %d: skrot pliku dowodu nie pasuje", j)
	}
	root, _ := hex.DecodeString(rootHex)
	if !VerifyProof(n, t, chi[:], root, proof) {
		return Segment{}, fail("odcinek %d: dowod NIE przechodzi kontroli", j)
	}
	gaps, ok := rec["gaps"].([]any)
	if !ok {
		return Segment{}, fail("gaps: lista")
	}
	for _, g := range gaps {
		gap := objOf(g)
		if gap == nil || !hasKeys(gap, "from_node", "utc_stop", "utc_resume", "reason") {
			return Segment{}, fail("gaps: zle pola")
		}
		if _, err := intOf(gap["from_node"], "gaps.from_node", 0); err != nil {
			return Segment{}, err
		}
		if _, err := checkUTC(gap["utc_stop"], "gaps.utc_stop"); err != nil {
			return Segment{}, err
		}
		if _, err := checkUTC(gap["utc_resume"], "gaps.utc_resume"); err != nil {
			return Segment{}, err
		}
		if _, ok := gap["reason"].(string); !ok {
			return Segment{}, fail("gaps.reason: napis")
		}
	}
	sp := objOf(rec["speed"])
	if sp == nil || !hasKeys(sp, "nodes_per_s_min", "nodes_per_s_median", "nodes_per_s_max") {
		return Segment{}, fail("speed: zle pola")
	}
	var speed [3]int64
	for i, k := range []string{"nodes_per_s_min", "nodes_per_s_median", "nodes_per_s_max"} {
		if speed[i], err = intOf(sp[k], "speed."+k, 1); err != nil {
			return Segment{}, err
		}
	}
	if !(speed[0] <= speed[1] && speed[1] <= speed[2]) {
		return Segment{}, fail("speed: min <= mediana <= max")
	}
	if v := rec["ptb_offset_us"]; v != nil {
		if num, ok := v.(json.Number); !ok {
			return Segment{}, fail("ptb_offset_us: liczba albo null")
		} else if _, err := strconv.ParseInt(string(num), 10, 64); err != nil {
			return Segment{}, fail("ptb_offset_us: liczba albo null")
		}
	}
	if _, err := intOf(rec["k_assumed"], "k_assumed", 1); err != nil {
		return Segment{}, err
	}
	if c, err := intOf(rec["claim_permille"], "claim_permille", 0); err != nil || c != int64(ClaimPermille(t, int(lam))) {
		return Segment{}, fail("claim_permille nie wynika z t i lambda")
	}
	cov, err := CoveragePermille(n, speed[2], start, end)
	if err != nil {
		return Segment{}, err
	}
	if c, err := intOf(rec["coverage_permille"], "coverage_permille", 0); err != nil || c != cov {
		return Segment{}, fail("coverage_permille nie wynika z danych")
	}
	if _, err := intOf(rec["s_ref_nodes_per_s"], "s_ref_nodes_per_s", 1); err != nil {
		return Segment{}, err
	}
	out := Segment{J: j, Root: rootHex, UTCEnd: end}
	if opt.Signed {
		pub, err := B64Field(rec["key"], ed25519.PublicKeySize, "key")
		if err != nil {
			return Segment{}, err
		}
		sig, err := B64Field(rec["sig"], ed25519.SignatureSize, "sig")
		if err != nil {
			return Segment{}, err
		}
		key := rec["key"].(string)
		known := false
		for _, k := range opt.Keys {
			known = known || k == key
		}
		if !known {
			return Segment{}, fail("odcinek %d: klucz %s spoza historii kluczy operatora", j, key)
		}
		msg, err := SigningMessage(rec)
		if err != nil {
			return Segment{}, err
		}
		if !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
			return Segment{}, fail("odcinek %d: podpis NIE pasuje", j)
		}
		out.Key = key
	}
	return out, nil
}

// IsHex64 mowi, czy napis to 64 znaki hex (male litery).
func IsHex64(s string) bool { return hex64RE.MatchString(s) }

// ProofFile zwraca nazwe pliku dowodu z rekordu (<j>.proof w katalogu odcinkow provera).
func ProofFile(rec map[string]any) (string, error) {
	pf := objOf(rec["proof"])
	if pf == nil {
		return "", fail("proof: pola file i sha256")
	}
	return strOf(pf["file"], proofRE, "proof.file", "<j>.proof")
}
