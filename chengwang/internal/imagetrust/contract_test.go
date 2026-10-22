package imagetrust

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestContractIsAdvisoryAndContainsNoRequestAuthority(t *testing.T) {
	raw, err := json.Marshal(VerifyRequest{PolicyID: "policy", Approval: []byte("a"), Bundle: []byte("b"), TrustedRoot: []byte("c")})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 4 {
		t.Fatal("request authority surface changed")
	}
	for _, key := range []string{"policyId", "approval", "bundle", "trustedRoot"} {
		if _, ok := fields[key]; !ok {
			t.Fatal("request field missing")
		}
	}
	if MaxCatalogueBytes != 256<<10 || MaxApprovalBytes != 64<<10 || MaxBundleBytes != 1<<20 || MaxRootBytes != 1<<20 || MaxVerifyBodyBytes != 3<<20 {
		t.Fatal("HTTP/SDK input budget drift")
	}
	if !strings.HasPrefix(StatusBoundary, "ADVISORY_") || !strings.HasPrefix(VerifiedBoundary, "ADVISORY_") {
		t.Fatal("boundary no longer advisory")
	}
}

func TestContractErrorHasOnlySafeOutcomeClassification(t *testing.T) {
	var empty *Error
	if empty.Error() != string(CodeUnavailable) {
		t.Fatal("nil error behavior")
	}
	for _, code := range []Code{CodeInvalid, CodeForbidden, CodeLocked, CodeUnavailable, CodeConflict, CodeBusy, CodeAuditDegraded, CodeCanceled} {
		value := &Error{Code: code, StateMayHaveChanged: true}
		if value.Error() != string(code) {
			t.Fatal("error leaks implementation detail")
		}
	}
	raw, err := json.Marshal(Receipt{})
	if err != nil || strings.Contains(string(raw), `"verified":true`) || strings.Contains(string(raw), `"authorization":"ALLOWED"`) {
		t.Fatal("zero DTO claimed authority")
	}
}
