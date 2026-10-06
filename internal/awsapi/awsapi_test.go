package awsapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Przyklad z dokumentacji AWS „Signature Version 4" (IAM ListUsers,
// 2015-08-30, klucze przykladowe AKIDEXAMPLE) — ten sam co w beattime tests_kms.py.
func TestSignatureV4AWSExample(t *testing.T) {
	got := SignatureV4("GET", "/", "Action=ListUsers&Version=2010-05-08", map[string]string{
		"Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
		"Host":         "iam.amazonaws.com",
		"X-Amz-Date":   "20150830T123600Z",
	}, nil, "us-east-1", "iam", Credentials{AccessKey: "AKIDEXAMPLE",
		SecretKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}, "20150830T123600Z")
	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, " +
		"SignedHeaders=content-type;host;x-amz-date, " +
		"Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
	if got != want {
		t.Fatalf("SigV4:\n%s\noczekiwany:\n%s", got, want)
	}
}

// fakeAWS udaje KMS i DynamoDB na jednym serwerze testowym.
type fakeAWS struct {
	key     ed25519.PrivateKey
	item    map[string]map[string]string
	targets []string
	auth    []string
}

func (f *fakeAWS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	target := r.Header.Get("X-Amz-Target")
	f.targets = append(f.targets, target)
	f.auth = append(f.auth, r.Header.Get("Authorization")+"|"+r.Header.Get("X-Amz-Security-Token"))
	var in map[string]any
	body, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(body, &in)
	out := map[string]any{}
	switch target {
	case "TrentService.GetPublicKey":
		der := append([]byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00},
			f.key.Public().(ed25519.PublicKey)...)
		out = map[string]any{"PublicKey": base64.StdEncoding.EncodeToString(der),
			"KeySpec": "ECC_NIST_EDWARDS25519", "KeyUsage": "SIGN_VERIFY"}
	case "TrentService.Sign":
		if in["MessageType"] != "RAW" || in["SigningAlgorithm"] != "ED25519_SHA_512" {
			w.WriteHeader(400)
			return
		}
		msg, _ := base64.StdEncoding.DecodeString(in["Message"].(string))
		out = map[string]any{"Signature": base64.StdEncoding.EncodeToString(ed25519.Sign(f.key, msg))}
	case "DynamoDB_20120810.GetItem":
		if f.item != nil {
			out = map[string]any{"Item": f.item}
		}
	case "DynamoDB_20120810.PutItem":
		want := in["ExpressionAttributeValues"].(map[string]any)[":v"].(map[string]any)["N"]
		if f.item != nil && f.item["version"]["N"] != want {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"__type":"com.amazonaws.dynamodb.v20120810#ConditionalCheckFailedException","message":"The conditional request failed"}`))
			return
		}
		item := in["Item"].(map[string]any)
		f.item = map[string]map[string]string{}
		for k, v := range item {
			for typ, val := range v.(map[string]any) {
				f.item[k] = map[string]string{typ: val.(string)}
			}
		}
	}
	_ = json.NewEncoder(w).Encode(out)
}

func newClient(f *fakeAWS) (*Client, *httptest.Server) {
	srv := httptest.NewServer(f)
	return &Client{Region: "eu-central-1", Cred: Credentials{"AKID", "SECRET", "TOKEN"},
		Endpoint: func(string) string { return srv.URL },
		Now:      func() time.Time { return time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC) }}, srv
}

func TestKMSAndDynamo(t *testing.T) {
	f := &fakeAWS{key: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x33}, 32))}
	c, srv := newClient(f)
	defer srv.Close()
	ctx := context.Background()

	pub, err := c.KMSPublicKey(ctx, "key-id")
	if err != nil || !pub.Equal(f.key.Public()) {
		t.Fatalf("klucz publiczny: %v", err)
	}
	sig, err := c.KMSSign(ctx, "key-id", []byte("hello"))
	if err != nil || !ed25519.Verify(pub, []byte("hello"), sig) {
		t.Fatalf("podpis: %v", err)
	}
	if _, err := c.KMSSign(ctx, "key-id", make([]byte, 4097)); err == nil {
		t.Fatal("przyjeto wiadomosc ponad limit RAW")
	}

	if _, _, ok, err := c.DynamoGet(ctx, "t", "state"); err != nil || ok {
		t.Fatalf("pusta tabela: ok=%v err=%v", ok, err)
	}
	if err := c.DynamoPut(ctx, "t", "state", `{"a":1}`, 0); err != nil {
		t.Fatal(err)
	}
	doc, version, ok, err := c.DynamoGet(ctx, "t", "state")
	if err != nil || !ok || doc != `{"a":1}` || version != 1 {
		t.Fatalf("odczyt: %q v%d ok=%v err=%v", doc, version, ok, err)
	}
	if err := c.DynamoPut(ctx, "t", "state", `{"a":2}`, 0); !errors.Is(err, ErrConflict) {
		t.Fatalf("zapis na starej wersji: %v", err)
	}
	for _, a := range f.auth {
		if !strings.HasPrefix(a, "AWS4-HMAC-SHA256 Credential=AKID/20261006/eu-central-1/") ||
			!strings.Contains(a, "x-amz-security-token") || !strings.HasSuffix(a, "|TOKEN") {
			t.Fatalf("naglowek autoryzacji: %s", a)
		}
	}
}
