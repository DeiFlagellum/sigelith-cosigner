// Package awsapi: trzy wywolania AWS, ktorych potrzebuje straznik w Lambdzie —
// KMS Sign i GetPublicKey (klucz Ed25519 w HSM) oraz DynamoDB GetItem/PutItem
// (stan straznika) — podpisane recznie (AWS Signature Version 4), bez SDK.
// Mniej kodu do zaufania; zgodnosc SigV4 pilnuje przyklad z dokumentacji AWS.
package awsapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// Credentials: z roli Lambdy (zmienne srodowiskowe, ktore ustawia AWS).
type Credentials struct {
	AccessKey, SecretKey, SessionToken string
}

// FromEnv czyta AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN.
func FromEnv() (Credentials, error) {
	c := Credentials{os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY"), os.Getenv("AWS_SESSION_TOKEN")}
	if c.AccessKey == "" || c.SecretKey == "" {
		return c, errors.New("brak poswiadczen AWS w srodowisku (rola Lambdy)")
	}
	return c, nil
}

func hmacSHA256(key []byte, text string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(text))
	return m.Sum(nil)
}

// SignatureV4 zwraca naglowek Authorization dla zadania. `headers` musza juz
// zawierac host i x-amz-date; wszystkie ida do podpisu.
func SignatureV4(method, path, query string, headers map[string]string, body []byte,
	region, service string, cred Credentials, amzDate string) string {
	lower := map[string]string{}
	names := make([]string, 0, len(headers))
	for k, v := range headers {
		name := strings.ToLower(k)
		lower[name] = strings.Join(strings.Fields(v), " ")
		names = append(names, name)
	}
	sort.Strings(names)
	var canon strings.Builder
	for _, n := range names {
		canon.WriteString(n + ":" + lower[n] + "\n")
	}
	signed := strings.Join(names, ";")
	bodyHash := sha256.Sum256(body)
	request := strings.Join([]string{method, path, query, canon.String(), signed, hex.EncodeToString(bodyHash[:])}, "\n")
	date := amzDate[:8]
	scope := date + "/" + region + "/" + service + "/aws4_request"
	reqHash := sha256.Sum256([]byte(request))
	toSign := strings.Join([]string{"AWS4-HMAC-SHA256", amzDate, scope, hex.EncodeToString(reqHash[:])}, "\n")
	key := hmacSHA256([]byte("AWS4"+cred.SecretKey), date)
	for _, part := range []string{region, service, "aws4_request"} {
		key = hmacSHA256(key, part)
	}
	sig := hex.EncodeToString(hmacSHA256(key, toSign))
	return "AWS4-HMAC-SHA256 Credential=" + cred.AccessKey + "/" + scope +
		", SignedHeaders=" + signed + ", Signature=" + sig
}

// Client wola JSON-owe API AWS (KMS, DynamoDB) w jednym regionie.
type Client struct {
	Region   string
	Cred     Credentials
	HTTP     *http.Client
	Endpoint func(service string) string // tylko testy; domyslnie https://<svc>.<region>.amazonaws.com
	Now      func() time.Time
}

// AWSError to odpowiedz bledu AWS (typ i komunikat).
type AWSError struct {
	Status  int
	Type    string
	Message string
}

func (e *AWSError) Error() string { return fmt.Sprintf("AWS %d %s: %s", e.Status, e.Type, e.Message) }

func (c *Client) call(ctx context.Context, service, contentType, target string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	base := "https://" + service + "." + c.Region + ".amazonaws.com"
	if c.Endpoint != nil {
		base = c.Endpoint(service)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/", bytes.NewReader(body))
	if err != nil {
		return err
	}
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	amzDate := now().UTC().Format("20060102T150405Z")
	host := service + "." + c.Region + ".amazonaws.com"
	headers := map[string]string{
		"Content-Type": contentType,
		"Host":         host,
		"X-Amz-Date":   amzDate,
		"X-Amz-Target": target,
	}
	if c.Cred.SessionToken != "" {
		headers["X-Amz-Security-Token"] = c.Cred.SessionToken
	}
	for k, v := range headers {
		if k != "Host" {
			req.Header.Set(k, v)
		}
	}
	req.Host = host
	req.Header.Set("Authorization", SignatureV4("POST", "/", "", headers, body, c.Region, service, c.Cred, amzDate))
	httpc := c.HTTP
	if httpc == nil {
		httpc = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := httpc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Type    string `json:"__type"`
			Message string `json:"message"`
			Msg     string `json:"Message"`
		}
		_ = json.Unmarshal(data, &e)
		msg := e.Message
		if msg == "" {
			msg = e.Msg
		}
		typ := e.Type
		if i := strings.LastIndex(typ, "#"); i >= 0 {
			typ = typ[i+1:]
		}
		return &AWSError{Status: resp.StatusCode, Type: typ, Message: msg}
	}
	return json.Unmarshal(data, out)
}

// spkiPrefix to naglowek DER klucza publicznego Ed25519 (RFC 8410).
var spkiPrefix = []byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}

// KMSPublicKey pobiera klucz publiczny i sprawdza, ze to Ed25519 do podpisu.
func (c *Client) KMSPublicKey(ctx context.Context, keyID string) (ed25519.PublicKey, error) {
	var out struct {
		PublicKey string
		KeySpec   string
		KeyUsage  string
	}
	if err := c.call(ctx, "kms", "application/x-amz-json-1.1", "TrentService.GetPublicKey",
		map[string]any{"KeyId": keyID}, &out); err != nil {
		return nil, err
	}
	if out.KeySpec != "ECC_NIST_EDWARDS25519" || out.KeyUsage != "SIGN_VERIFY" {
		return nil, fmt.Errorf("klucz KMS to %s/%s, a nie ECC_NIST_EDWARDS25519/SIGN_VERIFY", out.KeySpec, out.KeyUsage)
	}
	der, err := base64.StdEncoding.DecodeString(out.PublicKey)
	if err != nil || len(der) != len(spkiPrefix)+ed25519.PublicKeySize || !bytes.HasPrefix(der, spkiPrefix) {
		return nil, errors.New("KMS zwrocil klucz publiczny w nieoczekiwanej postaci")
	}
	return ed25519.PublicKey(der[len(spkiPrefix):]), nil
}

// KMSSign podpisuje wiadomosc czystym Ed25519 (RFC 8032): ED25519_SHA_512
// z MessageType RAW. Limit RAW w KMS to 4096 bajtow — dluzszych nie skracamy.
func (c *Client) KMSSign(ctx context.Context, keyID string, msg []byte) ([]byte, error) {
	if len(msg) > 4096 {
		return nil, errors.New("wiadomosc ponad 4096 bajtow (limit RAW w KMS)")
	}
	var out struct{ Signature string }
	if err := c.call(ctx, "kms", "application/x-amz-json-1.1", "TrentService.Sign", map[string]any{
		"KeyId": keyID, "Message": base64.StdEncoding.EncodeToString(msg),
		"MessageType": "RAW", "SigningAlgorithm": "ED25519_SHA_512",
	}, &out); err != nil {
		return nil, err
	}
	sig, err := base64.StdEncoding.DecodeString(out.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, errors.New("KMS zwrocil podpis w nieoczekiwanej postaci")
	}
	return sig, nil
}

// DynamoGet czyta dokument stanu: (tresc, wersja, czy istnieje).
func (c *Client) DynamoGet(ctx context.Context, table, pk string) (string, int64, bool, error) {
	var out struct {
		Item map[string]map[string]string
	}
	if err := c.call(ctx, "dynamodb", "application/x-amz-json-1.0", "DynamoDB_20120810.GetItem", map[string]any{
		"TableName": table, "ConsistentRead": true,
		"Key": map[string]any{"pk": map[string]string{"S": pk}},
	}, &out); err != nil {
		return "", 0, false, err
	}
	if out.Item == nil {
		return "", 0, false, nil
	}
	var version int64
	if _, err := fmt.Sscan(out.Item["version"]["N"], &version); err != nil {
		return "", 0, false, errors.New("stan w DynamoDB bez wersji")
	}
	return out.Item["doc"]["S"], version, true, nil
}

// ErrConflict: ktos zapisal stan w miedzyczasie (drugi przebieg naraz).
var ErrConflict = errors.New("stan zmienil sie w trakcie przebiegu")

// DynamoPut zapisuje dokument z wersja version+1 tylko wtedy, gdy w tabeli
// jest nadal wersja `version` (albo nic, przy pierwszym zapisie).
func (c *Client) DynamoPut(ctx context.Context, table, pk, doc string, version int64) error {
	err := c.call(ctx, "dynamodb", "application/x-amz-json-1.0", "DynamoDB_20120810.PutItem", map[string]any{
		"TableName": table,
		"Item": map[string]any{
			"pk":      map[string]string{"S": pk},
			"doc":     map[string]string{"S": doc},
			"version": map[string]string{"N": fmt.Sprint(version + 1)},
		},
		"ConditionExpression":       "attribute_not_exists(pk) OR version = :v",
		"ExpressionAttributeValues": map[string]any{":v": map[string]string{"N": fmt.Sprint(version)}},
	}, &struct{}{})
	var aerr *AWSError
	if errors.As(err, &aerr) && aerr.Type == "ConditionalCheckFailedException" {
		return ErrConflict
	}
	return err
}
