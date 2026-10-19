package restorecurrent

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
)

const (
	candidateIdentitySchemaV1 = "chengwang.m2b-candidate-identity/v1"
	maxCandidateIdentityBytes = 32 << 10
)

var (
	candidateIDPattern = regexp.MustCompile(`^candidate-[0-9a-f]{32}$`)
	noncePattern       = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type candidateIdentity struct {
	Schema             string `json:"schema"`
	CandidateID        string `json:"candidateId"`
	Instance           string `json:"instance"`
	CandidateRoot      string `json:"candidateRoot"`
	ProjectName        string `json:"projectName"`
	ServiceName        string `json:"serviceName"`
	StateMountTarget   string `json:"stateMountTarget"`
	IdentityGeneration uint64 `json:"identityGeneration"`
	GenesisNonce       string `json:"genesisNonce"`
}

func parseCandidateIdentity(raw []byte, candidateRoot, instance, projectName string) (candidateIdentity, error) {
	if len(raw) == 0 || len(raw) > maxCandidateIdentityBytes {
		return candidateIdentity{}, errors.Join(ErrInvalid, errors.New("candidate identity size is invalid"))
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return candidateIdentity{}, errors.Join(ErrInvalid, errors.New("candidate identity JSON is invalid"))
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil || !exactIdentityKeys(keys) {
		return candidateIdentity{}, errors.Join(ErrInvalid, errors.New("candidate identity field set is invalid"))
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var value candidateIdentity
	if err := decoder.Decode(&value); err != nil {
		return candidateIdentity{}, errors.Join(ErrInvalid, errors.New("candidate identity value types are invalid"))
	}
	if value.Schema != candidateIdentitySchemaV1 || value.IdentityGeneration != 1 ||
		value.Instance != instance || value.CandidateRoot != candidateRoot ||
		value.ProjectName != projectName || value.ServiceName != serviceName ||
		value.StateMountTarget != stateMountTarget || !noncePattern.MatchString(value.GenesisNonce) ||
		value.GenesisNonce == strings.Repeat("0", 64) {
		return candidateIdentity{}, errors.Join(ErrInvalid, errors.New("candidate identity binding is invalid"))
	}
	want := deriveCandidateID(candidateRoot, value.GenesisNonce)
	if !candidateIDPattern.MatchString(value.CandidateID) || value.CandidateID != want {
		return candidateIdentity{}, errors.Join(ErrInvalid, errors.New("candidate identity identifier is invalid"))
	}
	return value, nil
}

func exactIdentityKeys(keys map[string]json.RawMessage) bool {
	want := []string{
		"schema", "candidateId", "instance", "candidateRoot", "projectName",
		"serviceName", "stateMountTarget", "identityGeneration", "genesisNonce",
	}
	if len(keys) != len(want) {
		return false
	}
	for _, key := range want {
		if _, ok := keys[key]; !ok {
			return false
		}
	}
	return true
}

func deriveCandidateID(candidateRoot, nonce string) string {
	sum := sha256.Sum256([]byte(candidateIdentitySchemaV1 + "\x00" + candidateRoot + "\x00" + nonce))
	return "candidate-" + hex.EncodeToString(sum[:16])
}
