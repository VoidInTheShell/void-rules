// SPDX-License-Identifier: MIT
package main

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func writeFixture(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSelectedTags(t *testing.T) {
	selected := selectedTags(" AI,Finance,ai ")
	if !tagSelected(selected, "ai") || !tagSelected(selected, "FINANCE") {
		t.Fatalf("unexpected selected tag set: %#v", selected)
	}
	if tagSelected(selected, "other") {
		t.Fatal("unexpected match for unselected tag")
	}
}

func TestGeositeRoundTrip(t *testing.T) {
	directory := t.TempDir()
	input := filepath.Join(directory, "input.jsonl")
	dat := filepath.Join(directory, "geosite.dat")
	output := filepath.Join(directory, "output.jsonl")
	content := "" +
		`{"tag":"fixture","kind":"domain_suffix","value":"example.com","attributes":["test"]}` + "\n" +
		`{"tag":"fixture","kind":"domain_regex","value":"^api\\..+$"}` + "\n"
	if err := os.WriteFile(input, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := encodeGeosite(input, dat); err != nil {
		t.Fatal(err)
	}
	if err := decodeGeosite(dat, output, "fixture"); err != nil {
		t.Fatal(err)
	}
	records, err := readJSONL(output)
	if err != nil {
		t.Fatal(err)
	}
	expected := []record{
		{Tag: "fixture", Kind: "domain_regex", Value: `^api\..+$`},
		{Tag: "fixture", Kind: "domain_suffix", Value: "example.com", Attributes: []string{"test"}},
	}
	if !reflect.DeepEqual(records, expected) {
		t.Fatalf("round trip mismatch:\nactual=%#v\nexpected=%#v", records, expected)
	}
}

func TestGeoIPRoundTrip(t *testing.T) {
	directory := t.TempDir()
	input := filepath.Join(directory, "input.jsonl")
	dat := filepath.Join(directory, "geoip.dat")
	output := filepath.Join(directory, "output.jsonl")
	content := "" +
		`{"tag":"fixture","kind":"ip_cidr","value":"192.0.2.0/24"}` + "\n" +
		`{"tag":"fixture","kind":"ip_cidr","value":"2001:db8::/32"}` + "\n"
	if err := os.WriteFile(input, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := encodeGeoIP(input, dat); err != nil {
		t.Fatal(err)
	}
	if err := decodeGeoIP(dat, output, "fixture"); err != nil {
		t.Fatal(err)
	}
	records, err := readJSONL(output)
	if err != nil {
		t.Fatal(err)
	}
	expected := []record{
		{Tag: "fixture", Kind: "ip_cidr", Value: "192.0.2.0/24"},
		{Tag: "fixture", Kind: "ip_cidr", Value: "2001:db8::/32"},
	}
	if !reflect.DeepEqual(records, expected) {
		t.Fatalf("round trip mismatch:\nactual=%#v\nexpected=%#v", records, expected)
	}
}

func TestReadJSONLRejectsMissingRequiredField(t *testing.T) {
	path := writeFixture(t, "bad.jsonl", `{"tag":"fixture","kind":"domain"}`+"\n")
	if _, err := readJSONL(path); err == nil {
		t.Fatal("expected missing value to fail")
	}
}

func TestGzipIsDeterministicAndRoundTrips(t *testing.T) {
	directory := t.TempDir()
	input := filepath.Join(directory, "input.txt")
	first := filepath.Join(directory, "first.gz")
	second := filepath.Join(directory, "second.gz")
	payload := bytes.Repeat([]byte("deterministic gzip fixture\n"), 100)
	if err := os.WriteFile(input, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := gzipFile(input, first); err != nil {
		t.Fatal(err)
	}
	if err := gzipFile(input, second); err != nil {
		t.Fatal(err)
	}
	firstData, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	secondData, err := os.ReadFile(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstData, secondData) {
		t.Fatal("gzip output is not deterministic")
	}
	reader, err := gzip.NewReader(bytes.NewReader(firstData))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, payload) {
		t.Fatal("gzip round trip mismatch")
	}
}
