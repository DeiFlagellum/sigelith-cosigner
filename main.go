// sigelith-cosigner - straznik dziennika Sigelith (PROTOCOL.md).
//
// Co minute pobiera nowe wpisy z publicznego dziennika, sprawdza lancuch
// i czas wedlug WLASNEGO zegara, liczy drzewo RFC 9162 i podpisuje stan
// (`sigelith-cosign-v1`). Podpis wysyla do dziennika, ktory moze go tylko
// przechowac i rozdac - podrobic nie moze. Straznik nie ma zadnych drzwi:
// nikt z zewnatrz nie kaze mu niczego podpisac.
//
// Od 1.1.0 sprawdza tez sam kazdy nowy odcinek kazdego zegara Klepsydry
// w dzienniku i podpisuje potwierdzenie (`sigelith-hourglass-confirm-v1`).
//
// Dwa tryby, jeden kod:
//   - u operatora (kontener): `sigelith-cosigner run`, klucz i stan w /data;
//   - w AWS Lambda (provided.al2023): klucz w KMS, stan w DynamoDB -
//     tryb wlacza sie sam, gdy jest AWS_LAMBDA_RUNTIME_API.
//
// Operator wlasnego zegara Klepsydry publikuje go tym samym programem
// (`clock-push`, osobny klucz clock.key; PROTOCOL.md 10).
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
	"strings"
	"syscall"
	"time"

	"sigelith.org/cosigner/internal/awsapi"
	"sigelith.org/cosigner/internal/clockpush"
	"sigelith.org/cosigner/internal/lambdart"
	"sigelith.org/cosigner/internal/runner"
	"sigelith.org/cosigner/internal/signer"
	"sigelith.org/cosigner/internal/store"
)

// version ustawia budowanie: -ldflags "-X main.version=1.1.0".
var version = "dev"

const usage = `sigelith-cosigner ` + "%s" + ` - straznik dziennika Sigelith

  run                           co minute: pobierz, sprawdz, podpisz, wyslij (domyslne)
  once                          jeden przebieg, wynik jako JSON
  pubkey                        wypisz klucz publiczny (tworzy klucz przy pierwszym uzyciu)
  clear-alarm                   zdejmij alarm dziennika po decyzji operatora (PROTOCOL.md 5)
  clear-hourglass-alarm <zegar> zdejmij alarm jednego zegara Klepsydry (PROTOCOL.md 9)
  clock-key                     wypisz klucz publiczny wlasnego zegara Klepsydry (tworzy clock.key)
  clock-push                    co minute: sprawdz, podpisz i wyslij nowe odcinki wlasnego zegara (PROTOCOL.md 10)
  clock-push-once               jeden przebieg clock-push, wynik jako JSON
  version                       wersja

Srodowisko: COSIGNER_NAME (wymagane dla run i once, [a-z0-9-]), LOG_URL (https://sigelith.org),
COSIGNER_DATA (/data), INTERVAL_SECONDS (60), HOURGLASS (off = bez sprawdzania Klepsydry);
dla clock-push: CLOCK_NAME (nazwa zegara w dzienniku), CLOCK_DIR (/hourglass, katalog provera).
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
		Cfg: runner.Config{LogURL: env("LOG_URL", "https://sigelith.org"), Name: os.Getenv("COSIGNER_NAME"),
			HourglassOff: os.Getenv("HOURGLASS") == "off"},
		Store:  st,
		Signer: key,
		Logf:   log.Printf,
	}
	clockKey := &signer.File{Path: filepath.Join(data, "clock.key")}
	pusher := &clockpush.Pusher{
		Cfg: clockpush.Config{LogURL: env("LOG_URL", "https://sigelith.org"), Clock: os.Getenv("CLOCK_NAME"),
			Dir: env("CLOCK_DIR", "/hourglass"), Version: version},
		Signer: clockKey,
		Logf:   log.Printf,
	}
	interval := 60 * time.Second
	if s, err := strconv.Atoi(env("INTERVAL_SECONDS", "60")); err == nil && s >= 30 {
		interval = time.Duration(s) * time.Second
	}
	ctx := context.Background()
	switch cmd {
	case "run":
		pub := mustPub(ctx, key)
		log.Printf("straznik %q, dziennik %s, klucz publiczny %s, co %s",
			r.Cfg.Name, r.Cfg.LogURL, pub, interval)
		every(ctx, interval, func(ctx context.Context) { report(r.RunOnce(ctx)) })
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
	case "clear-hourglass-alarm":
		if len(os.Args) != 3 {
			log.Fatal("uzycie: clear-hourglass-alarm <zegar>")
		}
		s, v, err := st.Load(ctx)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(runner.ClearHourglassAlarm(s, os.Args[2]))
		if _, err := st.Save(ctx, s, v); err != nil {
			log.Fatal(err)
		}
	case "clock-key":
		fmt.Println(mustPub(ctx, clockKey))
	case "clock-push":
		pub := mustPub(ctx, clockKey)
		log.Printf("zegar %q z katalogu %s, dziennik %s, klucz zegara %s, co %s",
			pusher.Cfg.Clock, pusher.Cfg.Dir, pusher.Cfg.LogURL, pub, interval)
		every(ctx, interval, func(ctx context.Context) { reportPush(pusher.RunOnce(ctx)) })
	case "clock-push-once":
		res, err := pusher.RunOnce(ctx)
		out, _ := json.Marshal(res)
		fmt.Println(string(out))
		if err != nil {
			log.Fatal(err)
		}
	case "version":
		fmt.Println(version)
	default:
		fmt.Fprintf(os.Stderr, usage, version)
		os.Exit(2)
	}
}

// every wywoluje f od razu, potem co interval, az do SIGTERM.
func every(ctx context.Context, interval time.Duration, f func(context.Context)) {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		f(ctx)
		select {
		case <-ctx.Done():
			log.Print("koniec")
			return
		case <-tick.C:
		}
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
	if res.HGConfirmed > 0 || res.HGDelivered > 0 || res.HGPending > 0 {
		log.Printf("klepsydra: potwierdzone odcinki %d, wyslane %d, w kolejce %d",
			res.HGConfirmed, res.HGDelivered, res.HGPending)
	}
	for _, a := range res.HGAlarms {
		log.Printf("klepsydra: zegar wstrzymany alarmem - %s", a)
	}
}

func reportPush(res clockpush.Result, err error) {
	switch {
	case err != nil:
		log.Printf("BLAD zegara: %v", err)
	case res.Waiting != "":
		log.Printf("zegar czeka: %s", res.Waiting)
	case res.Genesis || res.Pushed > 0:
		log.Printf("zegar: genesis %v, wyslane odcinki %d, ostatni w dzienniku %d", res.Genesis, res.Pushed, res.Latest)
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
		Cfg: runner.Config{LogURL: env("LOG_URL", "https://sigelith.org"), Name: need("COSIGNER_NAME"),
			HourglassOff: os.Getenv("HOURGLASS") == "off"},
		Store:  st,
		Signer: &signer.KMS{Client: client, KeyID: need("KMS_KEY_ID")},
		Logf:   log.Printf,
	}
	lambdart.Loop(func(ctx context.Context, event []byte) (any, error) {
		var ev struct {
			ClearAlarm          bool   `json:"clear_alarm"`
			ClearHourglassAlarm string `json:"clear_hourglass_alarm"`
		}
		_ = json.Unmarshal(event, &ev)
		if ev.ClearAlarm || ev.ClearHourglassAlarm != "" {
			s, v, err := st.Load(ctx)
			if err != nil {
				return nil, err
			}
			msg := ""
			if ev.ClearAlarm {
				msg = clearAlarm(s)
			} else {
				msg = runner.ClearHourglassAlarm(s, ev.ClearHourglassAlarm)
			}
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
		// Alarm zegara Klepsydry nie wstrzymuje podpisow dziennika, ale konczy wywolanie bledem,
		// zeby zadzialal alarm CloudWatch na metryce Errors (AWS.md 6).
		if len(res.HGAlarms) > 0 {
			return nil, errors.New("klepsydra: " + strings.Join(res.HGAlarms, "; "))
		}
		return res, nil
	})
}
