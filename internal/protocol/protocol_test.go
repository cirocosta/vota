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
