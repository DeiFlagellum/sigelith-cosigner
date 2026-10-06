// Package lambdart to minimalna petla Lambda Runtime API (srodowisko
// provided.al2023): pobierz zdarzenie, obsluz, odeslij wynik albo blad.
// Bez aws-lambda-go — cala obsluga to trzy zadania HTTP.
package lambdart

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)

// Handler obsluguje jedno wywolanie; blad = wywolanie nieudane (metryka Errors).
type Handler func(ctx context.Context, event []byte) (any, error)

// Loop obsluguje wywolania az do zamkniecia srodowiska.
func Loop(h Handler) {
	base := "http://" + os.Getenv("AWS_LAMBDA_RUNTIME_API") + "/2018-06-01/runtime/invocation/"
	client := &http.Client{} // GET next to dlugie oczekiwanie — bez limitu czasu
	for {
		resp, err := client.Get(base + "next")
		if err != nil {
			log.Fatalf("Runtime API: %v", err)
		}
		event, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		id := resp.Header.Get("Lambda-Runtime-Aws-Request-Id")
		ctx := context.Background()
		cancel := func() {}
		if ms, err := strconv.ParseInt(resp.Header.Get("Lambda-Runtime-Deadline-Ms"), 10, 64); err == nil {
			ctx, cancel = context.WithDeadline(ctx, time.UnixMilli(ms).Add(-500*time.Millisecond))
		}
		out, err := h(ctx, event)
		cancel()
		if err != nil {
			body, _ := json.Marshal(map[string]string{"errorMessage": err.Error(), "errorType": "CosignerError"})
			req, _ := http.NewRequest(http.MethodPost, base+id+"/error", bytes.NewReader(body))
			req.Header.Set("Lambda-Runtime-Function-Error-Type", "Unhandled")
			post(client, req)
			continue
		}
		body, _ := json.Marshal(out)
		req, _ := http.NewRequest(http.MethodPost, base+id+"/response", bytes.NewReader(body))
		post(client, req)
	}
}

func post(client *http.Client, req *http.Request) {
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Runtime API: %v", err)
		return
	}
	resp.Body.Close()
}
