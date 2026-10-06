package cosign

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
)

// Klucz testowy: seed 0x22 x 32 (wektor w PROTOCOL.md).
func testKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, 32))
}

func sample(key ed25519.PrivateKey) Body {
	return Body{
		Log:           "sigelith.org",
		Cosigner:      "example",
		Key:           base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)),
		Size:          3,
		Root:          "bda0c891af7812124648447e1402ec9a9af54ced96e5600ac017f01512d5428d",
		LastSeq:       4,
		LastChainHash: "e424f49b574def86c8ac3d14ec22cb8da83fac8b8a1c2f243ed71303402f5af2",
		Time:          "2026-09-28T12:01:00.250000Z",
		Since:         &Since{Size: 2, Time: "2026-09-28T12:00:00.100000Z"},
	}
}

func TestMessageIsCanonical(t *testing.T) {
	b := sample(testKey())
	msg, err := b.Message()
	if err != nil {
		t.Fatal(err)
	}
	want := `sigelith-cosign-v1|{"cosigner":"example","key":"` + b.Key + `","last_chain_hash":"e424f49b574def86c8ac3d14ec22cb8da83fac8b8a1c2f243ed71303402f5af2","last_seq":4,"log":"sigelith.org","root":"bda0c891af7812124648447e1402ec9a9af54ced96e5600ac017f01512d5428d","since":{"size":2,"time":"2026-09-28T12:00:00.100000Z"},"size":3,"time":"2026-09-28T12:01:00.250000Z","v":"sigelith-cosign-v1"}`
	if string(msg) != want {
		t.Fatalf("wiadomosc:\n%s\noczekiwana:\n%s", msg, want)
	}
	first := b
	first.Since = nil
	msg, _ = first.Message()
	if !strings.Contains(string(msg), `"since":null`) {
		t.Fatalf("pierwsza obserwacja bez since: %s", msg)
	}
}

func TestSignVerifyDocument(t *testing.T) {
	key := testKey()
	b := sample(key)
	msg, _ := b.Message()
	sig := ed25519.Sign(key, msg)
	if err := b.Verify(sig); err != nil {
		t.Fatal(err)
	}
	doc, err := b.Document(sig)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(doc), `,"v":"sigelith-cosign-v1"}`) || !strings.Contains(string(doc), `"sig":"`) {
		t.Fatalf("dokument: %s", doc)
	}
	tampered := b
	tampered.Size = 4
	if err := tampered.Verify(sig); err == nil {
		t.Fatal("podpis przeszedl po zmianie tresci")
	}
}

func TestValidateRejects(t *testing.T) {
	key := testKey()
	for name, mutate := range map[string]func(*Body){
		"nazwa":        func(b *Body) { b.Cosigner = "Zla Nazwa" },
		"klucz":        func(b *Body) { b.Key = "abc" },
		"root":         func(b *Body) { b.Root = "XYZ" },
		"czas":         func(b *Body) { b.Time = "2026-09-28T12:01:00Z" },
		"since.size":   func(b *Body) { b.Since.Size = 9 },
		"since.time":   func(b *Body) { b.Since.Time = "2026-09-29T00:00:00.000000Z" },
		"rozmiar zero": func(b *Body) { b.Size = 0 },
	} {
		b := sample(key)
		s := *b.Since
		b.Since = &s
		mutate(&b)
		if _, err := b.Message(); err == nil {
			t.Errorf("%s: przyjeto zla tresc", name)
		}
	}
}

// Wektor z PROTOCOL.md, sekcja 7 — zmiana formatu musi go zlamac.
func TestProtocolVector(t *testing.T) {
	b := sample(testKey())
	msg, _ := b.Message()
	sig := ed25519.Sign(testKey(), msg)
	const wantKey = "oJql9HpnWYAv+VX43C0qFKXJnSO+l/hkEn/5ODRVpPA="
	const wantSig = "RTmvqX92rz679pXAt9aFdN3GbHk4tiUh3y25i5YqCh3TPw99kOy1jVVYn3Bc0I/5uury+QWNQHgYHRLTzTPvCg=="
	if b.Key != wantKey || base64.StdEncoding.EncodeToString(sig) != wantSig {
		t.Fatalf("wektor sie zmienil: key %s sig %s", b.Key, base64.StdEncoding.EncodeToString(sig))
	}
}
