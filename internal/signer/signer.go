// Package signer: klucz straznika — 32-bajtowe ziarno Ed25519 w pliku
// (operator) albo klucz w AWS KMS (straznik w Lambdzie; klucz nie opuszcza HSM).
package signer

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"sync"

	"sigelith.org/cosigner/internal/awsapi"
)

// File to klucz w pliku. Plik powstaje przy pierwszym starcie (0600) i jest
// jedynym miejscem, w ktorym istnieje klucz prywatny — kopia tego pliku to
// kopia klucza.
type File struct {
	Path string
	once sync.Once
	key  ed25519.PrivateKey
	err  error
}

func (f *File) load() (ed25519.PrivateKey, error) {
	f.once.Do(func() {
		seed, err := os.ReadFile(f.Path)
		if errors.Is(err, os.ErrNotExist) {
			seed = make([]byte, ed25519.SeedSize)
			if _, err = rand.Read(seed); err != nil {
				f.err = err
				return
			}
			// O_EXCL: dwa starty naraz nie wytworza dwoch roznych kluczy.
			fh, err := os.OpenFile(f.Path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				f.err = fmt.Errorf("nie utworzono klucza %s: %w", f.Path, err)
				return
			}
			if _, err = fh.Write(seed); err == nil {
				err = fh.Sync()
			}
			if cerr := fh.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				f.err = err
				return
			}
		} else if err != nil {
			f.err = err
			return
		}
		if len(seed) != ed25519.SeedSize {
			f.err = fmt.Errorf("%s: klucz musi miec %d bajtow", f.Path, ed25519.SeedSize)
			return
		}
		f.key = ed25519.NewKeyFromSeed(seed)
	})
	return f.key, f.err
}

// PublicKey zwraca klucz publiczny (tworzy klucz przy pierwszym uzyciu).
func (f *File) PublicKey(context.Context) (ed25519.PublicKey, error) {
	key, err := f.load()
	if err != nil {
		return nil, err
	}
	return key.Public().(ed25519.PublicKey), nil
}

// Sign podpisuje wiadomosc.
func (f *File) Sign(_ context.Context, msg []byte) ([]byte, error) {
	key, err := f.load()
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(key, msg), nil
}

// KMS to klucz ECC_NIST_EDWARDS25519 w AWS KMS.
type KMS struct {
	Client *awsapi.Client
	KeyID  string
	once   sync.Once
	pub    ed25519.PublicKey
	err    error
}

// PublicKey pobiera klucz publiczny raz na zycie procesu.
func (k *KMS) PublicKey(ctx context.Context) (ed25519.PublicKey, error) {
	k.once.Do(func() { k.pub, k.err = k.Client.KMSPublicKey(ctx, k.KeyID) })
	return k.pub, k.err
}

// Sign prosi KMS o podpis (czysty Ed25519).
func (k *KMS) Sign(ctx context.Context, msg []byte) ([]byte, error) {
	return k.Client.KMSSign(ctx, k.KeyID, msg)
}
