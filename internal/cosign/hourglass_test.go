package cosign

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
)

// Wektor z PROTOCOL.md 9: odcinek 1 przykladowego ciagu v1 z wektorow Klepsydry.
func sampleConfirmation(key ed25519.PrivateKey) Confirmation {
	return Confirmation{
		Log:      "sigelith.org",
		Cosigner: "example",
		Key:      base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)),
		Clock:    "example",
		Genesis:  "cffd45246dd3587f6758d83d98a6b3c326a7de8375f4f292a1a7b2ac33f67df3",
		J:        1,
		Root:     "98811eb2bf58bd526b46e2cc70edee67eed1cb0d448f5c46a87b138babc4fef7",
		Record:   "ad361cf1c947ae7020a093c0a463e6c33ddd3ab74f38483f64dcba1f2761d9c5",
		Time:     "2026-11-23T00:01:00.250000Z",
	}
}

func TestConfirmationVector(t *testing.T) {
	key := testKey()
	c := sampleConfirmation(key)
	msg, err := c.Message()
	if err != nil {
		t.Fatal(err)
	}
	want := `sigelith-hourglass-confirm-v1|{"clock":"example","cosigner":"example","genesis":"cffd45246dd3587f6758d83d98a6b3c326a7de8375f4f292a1a7b2ac33f67df3","j":1,"key":"oJql9HpnWYAv+VX43C0qFKXJnSO+l/hkEn/5ODRVpPA=","log":"sigelith.org","record":"ad361cf1c947ae7020a093c0a463e6c33ddd3ab74f38483f64dcba1f2761d9c5","root":"98811eb2bf58bd526b46e2cc70edee67eed1cb0d448f5c46a87b138babc4fef7","time":"2026-11-23T00:01:00.250000Z","v":"sigelith-hourglass-confirm-v1"}`
	if string(msg) != want {
		t.Fatalf("wiadomosc:\n%s\noczekiwana:\n%s", msg, want)
	}
	sig := ed25519.Sign(key, msg)
	if got := base64.StdEncoding.EncodeToString(sig); got != "BNcmZ7uWARNQUbIs7ojWDThSv4laLXuL/zl6+uO7D0STPJ6yt1LTqqh0Yf/vY8hkLRsN0CB9JZLTPfGXetwtBg==" {
		t.Fatalf("podpis inny niz w PROTOCOL.md: %s", got)
	}
	if err := c.Verify(sig); err != nil {
		t.Fatal(err)
	}
	doc, err := c.Document(sig)
	if err != nil || !strings.Contains(string(doc), `"sig":"BNcmZ7`) || strings.Contains(string(doc), " ") {
		t.Fatalf("dokument: %s %v", doc, err)
	}
	other := c
	other.J = 2
	if other.Verify(sig) == nil {
		t.Fatal("podpis pasuje do innej tresci")
	}
}

func TestConfirmationValidate(t *testing.T) {
	base := sampleConfirmation(testKey())
	for name, edit := range map[string]func(*Confirmation){
		"j zero":      func(c *Confirmation) { c.J = 0 },
		"zly zegar":   func(c *Confirmation) { c.Clock = "Zegar" },
		"zly korzen":  func(c *Confirmation) { c.Root = "xyz" },
		"zly rekord":  func(c *Confirmation) { c.Record = strings.ToUpper(c.Record) },
		"zly genesis": func(c *Confirmation) { c.Genesis = "" },
		"zly czas":    func(c *Confirmation) { c.Time = "2026-11-23T00:01:00Z" },
		"zly klucz":   func(c *Confirmation) { c.Key = "abc" },
	} {
		c := base
		edit(&c)
		if c.Validate() == nil {
			t.Fatalf("%s: przyjete", name)
		}
	}
}
