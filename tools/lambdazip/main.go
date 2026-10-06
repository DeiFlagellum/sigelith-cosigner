// lambdazip pakuje binarke `bootstrap` do ZIP dla AWS Lambda (provided.al2023)
// zawsze tak samo: stala data, stale prawa — ten sam bootstrap daje ten sam
// ZIP, wiec skrot paczki da sie porownac z wydaniem na GitHubie.
//
//	go run ./tools/lambdazip <bootstrap> <wynik.zip>
package main

import (
	"archive/zip"
	"crypto/sha256"
	"fmt"
	"os"
	"time"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "uzycie: lambdazip <bootstrap> <wynik.zip>")
		os.Exit(2)
	}
	bin, err := os.ReadFile(os.Args[1])
	if err != nil {
		fail(err)
	}
	out, err := os.Create(os.Args[2])
	if err != nil {
		fail(err)
	}
	zw := zip.NewWriter(out)
	hdr := &zip.FileHeader{Name: "bootstrap", Method: zip.Deflate,
		Modified: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	hdr.SetMode(0o755)
	w, err := zw.CreateHeader(hdr)
	if err == nil {
		_, err = w.Write(bin)
	}
	if err == nil {
		err = zw.Close()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		fail(err)
	}
	data, _ := os.ReadFile(os.Args[2])
	fmt.Printf("%x  %s\n", sha256.Sum256(data), os.Args[2])
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
