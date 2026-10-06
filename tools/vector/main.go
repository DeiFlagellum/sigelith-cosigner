// vector wypisuje wektor testowy z PROTOCOL.md (sekcja 7): podpis straznika
// nad trzema wpisami z beattime LOG.md (sekcja 10), klucz testowy 0x22 x 32.
//
//	go run ./tools/vector
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"

	"sigelith.org/cosigner/internal/cosign"
)

// Body to wektor — ten sam w PROTOCOL.md i w testach.
func Body() (cosign.Body, ed25519.PrivateKey) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, 32))
	return cosign.Body{
		Log:           "sigelith.org",
		Cosigner:      "example",
		Key:           base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)),
		Size:          3,
		Root:          "bda0c891af7812124648447e1402ec9a9af54ced96e5600ac017f01512d5428d",
		LastSeq:       4,
		LastChainHash: "e424f49b574def86c8ac3d14ec22cb8da83fac8b8a1c2f243ed71303402f5af2",
		Time:          "2026-09-28T12:01:00.250000Z",
		Since:         &cosign.Since{Size: 2, Time: "2026-09-28T12:00:00.100000Z"},
	}, key
}

func main() {
	body, key := Body()
	msg, err := body.Message()
	if err != nil {
		panic(err)
	}
	sig := ed25519.Sign(key, msg)
	doc, err := body.Document(sig)
	if err != nil {
		panic(err)
	}
	fmt.Printf("key:      %s\nmessage:  %s\nsig:      %s\ndocument: %s\n",
		body.Key, msg, base64.StdEncoding.EncodeToString(sig), doc)
}
