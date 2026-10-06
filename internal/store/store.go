// Package store przechowuje stan straznika: plik JSON u operatora albo
// dokument w DynamoDB w AWS. Oba zapisuja atomowo — przerwany zapis nie
// zostawia polowy stanu.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"sigelith.org/cosigner/internal/awsapi"
	"sigelith.org/cosigner/internal/runner"
)

func empty() *runner.State { return &runner.State{Edges: []string{}, Outbox: []string{}} }

// File trzyma stan w jednym pliku (jedna instancja na katalog danych).
type File struct{ Path string }

// Load czyta stan; brak pliku = pierwszy start.
func (f File) Load(context.Context) (*runner.State, int64, error) {
	data, err := os.ReadFile(f.Path)
	if errors.Is(err, os.ErrNotExist) {
		return empty(), 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	st := empty()
	if err := json.Unmarshal(data, st); err != nil {
		return nil, 0, fmt.Errorf("%s: %w", f.Path, err)
	}
	return st, 0, nil
}

// Save zapisuje przez plik tymczasowy, fsync i podmiane nazwy.
func (f File) Save(_ context.Context, st *runner.State, _ int64) (int64, error) {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return 0, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(f.Path), ".state-*")
	if err != nil {
		return 0, err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return 0, err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return 0, err
	}
	if err := tmp.Close(); err != nil {
		return 0, err
	}
	return 0, os.Rename(tmp.Name(), f.Path)
}

// Dynamo trzyma stan jako jeden element tabeli (klucz `pk` = "state").
// Zapis warunkowy po wersji: dwa przebiegi naraz nie nadpisza sie nawzajem.
type Dynamo struct {
	Client *awsapi.Client
	Table  string
}

// Load czyta stan i jego wersje.
func (d Dynamo) Load(ctx context.Context) (*runner.State, int64, error) {
	doc, version, ok, err := d.Client.DynamoGet(ctx, d.Table, "state")
	if err != nil || !ok {
		return empty(), 0, err
	}
	st := empty()
	if err := json.Unmarshal([]byte(doc), st); err != nil {
		return nil, 0, fmt.Errorf("stan w DynamoDB: %w", err)
	}
	return st, version, nil
}

// Save zapisuje stan, jesli w tabeli jest nadal wersja `version`.
func (d Dynamo) Save(ctx context.Context, st *runner.State, version int64) (int64, error) {
	data, err := json.Marshal(st)
	if err != nil {
		return version, err
	}
	if err := d.Client.DynamoPut(ctx, d.Table, "state", string(data), version); err != nil {
		return version, err
	}
	return version + 1, nil
}
