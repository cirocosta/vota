package protocol

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type negativeCase struct {
	Name         string `json:"name"`
	Artifact     string `json:"artifact"`
	Mutation     string `json:"mutation"`
	ExpectedCode string `json:"expected_code"`
}

func TestDomainSeparatorsAreUnique(t *testing.T) {
	t.Parallel()

	domains := DomainSeparators()
	seen := make(map[string]struct{}, len(domains))
	for _, domain := range domains {
		if _, exists := seen[domain]; exists {
			t.Errorf("duplicate domain separator %q", domain)
		}
		seen[domain] = struct{}{}
	}
}

func TestMarshalCanonicalOrdersObjectKeys(t *testing.T) {
	t.Parallel()

	got, err := MarshalCanonical(map[string]any{"z": 1, "a": "first"})
	if err != nil {
		t.Fatalf("marshal canonical: %v", err)
	}
	want := []byte(`{"a":"first","z":1}`)
	if !bytes.Equal(got, want) {
		t.Fatalf("canonical JSON = %s, want %s", got, want)
	}
}

func TestDecodeStrictRejectsDuplicateAndUnknownFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data string
		code string
	}{
		{"duplicate", `{"schema_version":1,"schema_version":1}`, "duplicate_json_field"},
		{"unknown", `{"unknown":true}`, "invalid_json"},
		{"trailing", `{} {}`, "trailing_json"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var manifest Manifest
			err := DecodeStrict([]byte(test.data), &manifest)
			if ErrorCode(err) != test.code {
				t.Errorf("error = %v, code = %q, want %q", err, ErrorCode(err), test.code)
			}
		})
	}
}

func TestDecodeStrictLimitAllowsLargerContainer(t *testing.T) {
	t.Parallel()

	encoded := []byte(`"` + strings.Repeat("a", MaxArtifactBytes) + `"`)
	var value string
	if err := DecodeStrict(encoded, &value); ErrorCode(err) != "artifact_too_large" {
		t.Fatalf("default error = %v", err)
	}
	if err := DecodeStrictLimit(encoded, &value, 2<<20); err != nil {
		t.Fatalf("larger limit: %v", err)
	}
}

func TestStrictHexDecoders(t *testing.T) {
	t.Parallel()

	fixedValue := "sha256:" + strings.Repeat("a", 64)
	fixed, err := DecodeFixedHex("sha256", fixedValue, 32)
	if err != nil {
		t.Fatalf("decode fixed hex: %v", err)
	}
	if len(fixed) != 32 {
		t.Fatalf("fixed length = %d, want 32", len(fixed))
	}

	opaque, err := DecodeOpaqueHex("vota-elgamal-v1", "vota-elgamal-v1:00aa")
	if err != nil {
		t.Fatalf("decode opaque hex: %v", err)
	}
	if !bytes.Equal(opaque, []byte{0x00, 0xaa}) {
		t.Fatalf("opaque = %x, want 00aa", opaque)
	}

	raw, err := DecodeRawHex("00aa", 2)
	if err != nil {
		t.Fatalf("decode raw hex: %v", err)
	}
	if !bytes.Equal(raw, []byte{0x00, 0xaa}) {
		t.Fatalf("raw = %x, want 00aa", raw)
	}
	rawVariable, err := DecodeRawHex("ff", -1)
	if err != nil {
		t.Fatalf("decode variable raw hex: %v", err)
	}
	if !bytes.Equal(rawVariable, []byte{0xff}) {
		t.Fatalf("variable raw = %x, want ff", rawVariable)
	}

	tests := []struct {
		name   string
		decode func() error
	}{
		{
			name: "fixed wrong prefix",
			decode: func() error {
				_, err := DecodeFixedHex("sha256", "ristretto255:"+strings.Repeat("a", 64), 32)
				return err
			},
		},
		{
			name: "fixed wrong length",
			decode: func() error {
				_, err := DecodeFixedHex("sha256", "sha256:00", 32)
				return err
			},
		},
		{
			name: "fixed uppercase",
			decode: func() error {
				_, err := DecodeFixedHex("sha256", "sha256:"+strings.Repeat("a", 62)+"AA", 32)
				return err
			},
		},
		{
			name: "fixed invalid hex",
			decode: func() error {
				_, err := DecodeFixedHex("sha256", "sha256:"+strings.Repeat("a", 63)+"z", 32)
				return err
			},
		},
		{
			name: "fixed negative length",
			decode: func() error {
				_, err := DecodeFixedHex("sha256", "sha256:00", -1)
				return err
			},
		},
		{
			name: "opaque wrong prefix",
			decode: func() error {
				_, err := DecodeOpaqueHex("vota-elgamal-v1", "sha256:00aa")
				return err
			},
		},
		{
			name: "opaque empty",
			decode: func() error {
				_, err := DecodeOpaqueHex("vota-elgamal-v1", "vota-elgamal-v1:")
				return err
			},
		},
		{
			name: "opaque odd length",
			decode: func() error {
				_, err := DecodeOpaqueHex("vota-elgamal-v1", "vota-elgamal-v1:0")
				return err
			},
		},
		{
			name: "opaque uppercase",
			decode: func() error {
				_, err := DecodeOpaqueHex("vota-elgamal-v1", "vota-elgamal-v1:00AA")
				return err
			},
		},
		{
			name: "opaque invalid hex",
			decode: func() error {
				_, err := DecodeOpaqueHex("vota-elgamal-v1", "vota-elgamal-v1:zz")
				return err
			},
		},
		{
			name: "raw wrong length",
			decode: func() error {
				_, err := DecodeRawHex("00", 2)
				return err
			},
		},
		{
			name: "raw empty variable",
			decode: func() error {
				_, err := DecodeRawHex("", -1)
				return err
			},
		},
		{
			name: "raw odd variable",
			decode: func() error {
				_, err := DecodeRawHex("0", -1)
				return err
			},
		},
		{
			name: "raw uppercase",
			decode: func() error {
				_, err := DecodeRawHex("00AA", 2)
				return err
			},
		},
		{
			name: "raw invalid hex",
			decode: func() error {
				_, err := DecodeRawHex("zz", -1)
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.decode(); err == nil {
				t.Errorf("decode succeeded, want error")
			}
		})
	}
}

func TestParseCanonicalTime(t *testing.T) {
	t.Parallel()

	parsed, err := ParseCanonicalTime("2026-08-01T12:00:00Z")
	if err != nil {
		t.Fatalf("parse canonical time: %v", err)
	}
	if got := parsed.UTC().Format("2006-01-02T15:04:05Z07:00"); got != "2026-08-01T12:00:00Z" {
		t.Fatalf("parsed time = %s, want 2026-08-01T12:00:00Z", got)
	}

	tests := []string{
		"2026-08-01T08:00:00-04:00",
		"2026-08-01T12:00:00.000Z",
		"not-a-time",
	}
	for _, value := range tests {
		t.Run(value, func(t *testing.T) {
			if _, err := ParseCanonicalTime(value); err == nil {
				t.Errorf("ParseCanonicalTime(%q) succeeded, want error", value)
			}
		})
	}
}

func TestReferenceElectionFixture(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "testdata", "protocol", "reference-election.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read reference election: %v", err)
	}
	var election ReferenceElection
	if err := DecodeStrict(data, &election); err != nil {
		t.Fatalf("decode reference election: %v", err)
	}
	if err := ValidateManifest(election.Manifest); err != nil {
		t.Fatalf("validate manifest: %v", err)
	}
	if len(election.Ballots) != 3 {
		t.Fatalf("ballot count = %d, want 3", len(election.Ballots))
	}
	for index, ballot := range election.Ballots {
		if err := ValidateBallotShape(election.Manifest, ballot); err != nil {
			t.Errorf("validate ballot %d: %v", index, err)
		}
	}
	if election.Tally.BallotCount != len(election.Ballots) {
		t.Errorf("tally ballot count = %d, want %d", election.Tally.BallotCount, len(election.Ballots))
	}
	if !slices.Equal(election.Tally.TrusteeIDs, []string{"t1", "t2"}) {
		t.Errorf("trustee IDs = %v", election.Tally.TrusteeIDs)
	}
}

func TestNegativeCaseCatalog(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "testdata", "protocol", "negative-cases.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read negative cases: %v", err)
	}
	var cases []negativeCase
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatalf("decode negative cases: %v", err)
	}
	wantNames := []string{
		"duplicate_eligibility_key",
		"duplicate_nullifier",
		"invalid_choice_proof",
		"malformed_point",
		"wrong_aggregate_hash",
		"wrong_manifest",
	}
	gotNames := make([]string, 0, len(cases))
	seen := make(map[string]struct{}, len(cases))
	for _, testCase := range cases {
		if testCase.Name == "" || testCase.Artifact == "" || testCase.Mutation == "" || testCase.ExpectedCode == "" {
			t.Errorf("incomplete negative case: %#v", testCase)
		}
		if _, exists := seen[testCase.Name]; exists {
			t.Errorf("duplicate negative case %q", testCase.Name)
		}
		seen[testCase.Name] = struct{}{}
		gotNames = append(gotNames, testCase.Name)
	}
	slices.Sort(gotNames)
	if !slices.Equal(gotNames, wantNames) {
		t.Errorf("negative cases = %v, want %v", gotNames, wantNames)
	}
}
