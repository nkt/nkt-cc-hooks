package main

import (
	"bufio"
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"testing"
)

// TestParityCorpus checks the secrets hook against verdicts recorded from a
// reference implementation, one JSON object per line:
//
//	{"kind":"bash","input":"cat .env","hits":[".env"]}
//	{"kind":"path","input":"/app/.env","secret":true}
//
// Point CC_HOOKS_PARITY at such a file to run it; it is skipped otherwise.
// Only the built-in rules are compared: no allow list, no glob detection.
func TestParityCorpus(t *testing.T) {
	path := os.Getenv("CC_HOOKS_PARITY")
	if path == "" {
		t.Skip("CC_HOOKS_PARITY not set")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	home, _ := os.UserHomeDir()
	cfg := secretsConfig{allow: map[string]bool{}}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 64<<20)
	var n, bad int
	for sc.Scan() {
		var c struct {
			Kind   string   `json:"kind"`
			Input  string   `json:"input"`
			Hits   []string `json:"hits"`
			Secret bool     `json:"secret"`
		}
		if err := json.Unmarshal(sc.Bytes(), &c); err != nil {
			t.Fatal(err)
		}
		n++
		switch c.Kind {
		case "bash":
			got := namedSecrets(c.Input, cfg)
			sort.Strings(got)
			got = dedupe(got)
			if len(got) == 0 && len(c.Hits) == 0 {
				continue
			}
			if !reflect.DeepEqual(got, c.Hits) {
				bad++
				if bad <= 40 {
					t.Errorf("bash %q: got %q, want %q", c.Input, got, c.Hits)
				}
			}
		case "path":
			if got := isSecretPath(c.Input, home, cfg); got != c.Secret {
				bad++
				if bad <= 40 {
					t.Errorf("path %q: got %v, want %v", c.Input, got, c.Secret)
				}
			}
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	t.Logf("%d cases, %d mismatches", n, bad)
}
