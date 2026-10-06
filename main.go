// sigelith-cosigner — straznik dziennika Sigelith (PROTOCOL.md).
//
// Co minute pobiera nowe wpisy z publicznego dziennika, sprawdza lancuch
// i czas wedlug WLASNEGO zegara, liczy drzewo RFC 9162 i podpisuje stan
// (`sigelith-cosign-v1`). Podpis wysyla do dziennika, ktory moze go tylko
// przechowac i rozdac — podrobic nie moze. Straznik nie ma zadnych drzwi:
// nikt z zewnatrz nie kaze mu niczego podpisac.
//
// Dwa tryby, jeden kod:
//   - u operatora (kontener): `sigelith-cosigner run`, klucz i stan w /data;
//   - w AWS Lambda (provided.al2023): klucz w KMS, stan w DynamoDB —
//     tryb wlacza sie sam, gdy jest AWS_LAMBDA_RUNTIME_API.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"sigelith.org/cosigner/internal/awsapi"
	"sigelith.org/cosigner/internal/lambdart"
	"sigelith.org/cosigner/internal/runner"
	"sigelith.org/cosigner/internal/signer"
	"sigelith.org/cosigner/internal/store"
)

// version ustawia budowanie: -ldflags "-X main.version=1.0.0".
var version = "dev"

const usage = `sigelith-cosigner ` + "%s" + ` — straznik dziennika Sigelith

  run          co minute: pobierz, sprawdz, podpisz, wyslij (domyslne)
  once         jeden przebieg, wynik jako JSON
  pubkey       wypisz klucz publiczny (tworzy klucz przy pierwszym uzyciu)
  clear-alarm  zdejmij alarm po decyzji operatora (PROTOCOL.md 5)
  version      wersja

Srodowisko: COSIGNER_NAME (wymagane, [a-z0-9-]), LOG_URL (https://sigelith.org),
COSIGNER_DATA (/data), INTERVAL_SECONDS (60).
`

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func main() {
	runner.Version = version
	log.SetFlags(log.LstdFlags | log.LUTC)
	if os.Getenv("AWS_LAMBDA_RUNTIME_API") != "" {
		lambdaMain()
		return
	}
	cmd := "run"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	data := env("COSIGNER_DATA", "/data")
	key := &signer.File{Path: filepath.Join(data, "cosigner.key")}
	st := store.File{Path: filepath.Join(data, "state.json")}
	r := &runner.Runner{
		Cfg:    runner.Config{LogURL: env("LOG_URL", "https://sigelith.org"), Name: os.Getenv("COSIGNER_NAME")},
		Store:  st,
		Signer: key,
		Logf:   log.Printf,
	}
	ctx := context.Background()
	switch cmd {
	case "run":
		pub := mustPub(ctx, key)
		interval := 60 * time.Second
		if s, err := strconv.Atoi(env("INTERVAL_SECONDS", "60")); err == nil && s >= 30 {
			interval = time.Duration(s) * time.Second
		}
		log.Printf("straznik %q, dziennik %s, klucz publiczny %s, co %s",
			r.Cfg.Name, r.Cfg.LogURL, pub, interval)
		ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
		defer stop()
		tick := time.NewTicker(interval)
		defer tick.Stop()
		for {
			report(r.RunOnce(ctx))
			select {
			case <-ctx.Done():
				log.Print("koniec")
				return
			case <-tick.C:
			}
		}
	case "once":
		res, err := r.RunOnce(ctx)
		out, _ := json.Marshal(res)
		fmt.Println(string(out))
		if err != nil {
			log.Fatal(err)
		}
	case "pubkey":
		fmt.Println(mustPub(ctx, key))
	case "clear-alarm":
		s, v, err := st.Load(ctx)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(clearAlarm(s))
		if _, err := st.Save(ctx, s, v); err != nil {
			log.Fatal(err)
		}
	case "version":
		fmt.Println(version)
	default:
		fmt.Fprintf(os.Stderr, usage, version)
		os.Exit(2)
	}
}

func mustPub(ctx context.Context, s runner.Signer) string {
	pub, err := s.PublicKey(ctx)
	if err != nil {
		log.Fatalf("klucz: %v", err)
	}
	return base64.StdEncoding.EncodeToString(pub)
}

func report(res runner.Result, err error) {
	if err != nil {
		log.Printf("BLAD: %v", err)
		return
	}
	if res.NewEntries > 0 || res.Signed || res.Delivered > 0 || res.Pending > 0 {
		log.Printf("nowe wpisy %d, rozmiar %d, podpis %v, wyslane %d, w kolejce %d",
			res.NewEntries, res.Size, res.Signed, res.Delivered, res.Pending)
	}
}

// clearAlarm zdejmuje alarm i dolna granice czasu: po bledzie zegara albo
// sporze nastepny podpis nie bedzie twierdzil niczego o poprzedniej obserwacji.
func clearAlarm(s *runner.State) string {
	if s.Alarm == "" {
		return "alarmu nie ma"
	}
	was := s.Alarm
	s.Alarm, s.ObservedAt = "", ""
	return "zdjety alarm: " + was
}

func lambdaMain() {
	need := func(name string) string {
		v := os.Getenv(name)
		if v == "" {
			log.Fatalf("brak zmiennej %s", name)
		}
		return v
	}
	cred, err := awsapi.FromEnv()
	if err != nil {
		log.Fatal(err)
	}
	client := &awsapi.Client{Region: need("AWS_REGION"), Cred: cred}
	st := store.Dynamo{Client: client, Table: need("STATE_TABLE")}
	r := &runner.Runner{
		Cfg:    runner.Config{LogURL: env("LOG_URL", "https://sigelith.org"), Name: need("COSIGNER_NAME")},
		Store:  st,
		Signer: &signer.KMS{Client: client, KeyID: need("KMS_KEY_ID")},
		Logf:   log.Printf,
	}
	lambdart.Loop(func(ctx context.Context, event []byte) (any, error) {
		var ev struct {
			ClearAlarm bool `json:"clear_alarm"`
		}
		_ = json.Unmarshal(event, &ev)
		if ev.ClearAlarm {
			s, v, err := st.Load(ctx)
			if err != nil {
				return nil, err
			}
			msg := clearAlarm(s)
			if _, err := st.Save(ctx, s, v); err != nil {
				return nil, err
			}
			return map[string]string{"result": msg}, nil
		}
		res, err := r.RunOnce(ctx)
		report(res, err)
		if err != nil {
			return nil, errors.New(err.Error())
		}
		return res, nil
	})
}
