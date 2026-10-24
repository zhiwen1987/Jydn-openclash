package mihomodeploy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLabLocalRouteRejectsArbitraryCONNECTAndDoesNotDial(t *testing.T) {
	f := newLabLocalFixture(strings.Repeat("a", 64), strings.Repeat("b", 64))
	for _, target := range []string{"example.org:443", "127.0.0.1:28416", "localhost:28415"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("CONNECT", "http://"+target, nil)
		r.Host = target
		r.RequestURI = target
		f.proxy("A", w, r)
		if w.Code != 403 {
			t.Fatal("arbitrary CONNECT accepted")
		}
	}
	s := f.snapshot()
	if s[0].ConnectIngress != 0 || s[0].Rejected != 3 || s[0].ForwardInvocations != 0 {
		t.Fatal("rejected destination caused forwarding")
	}
}
func TestLabLocalOriginRejectsUnknownOrForgedPrivateMarker(t *testing.T) {
	f := newLabLocalFixture(strings.Repeat("a", 64), strings.Repeat("b", 64))
	nonce := strings.Repeat("c", 64)
	for _, known := range []bool{false, true} {
		if known {
			f.expected[nonce] = "A"
		}
		r := httptest.NewRequest(http.MethodGet, "http://"+labLocalOrigin+"/marker?nonce="+nonce, nil)
		r.Header.Set(labLocalRouteHeader, "untrusted")
		w := httptest.NewRecorder()
		f.origin(w, r)
		if w.Code != 403 {
			t.Fatal("forged marker accepted")
		}
	}
	if f.snapshot()[2].OriginRequests != 0 {
		t.Fatal("forged origin treated as verified")
	}
}
func TestLabLocalOriginReturnsActualBoundBodyAndCountsSelectedRole(t *testing.T) {
	f := newLabLocalFixture(strings.Repeat("a", 64), strings.Repeat("b", 64))
	nonce := strings.Repeat("c", 64)
	f.expected[nonce] = "B"
	r := httptest.NewRequest(http.MethodGet, "http://"+labLocalOrigin+"/marker?nonce="+nonce, nil)
	r.Header.Set(labLocalRouteHeader, strings.Repeat("b", 64))
	w := httptest.NewRecorder()
	f.origin(w, r)
	if w.Code != 200 || w.Body.String() != string(labLocalMarker("B", nonce)) {
		t.Fatal("actual bound body changed")
	}
	s := f.snapshot()
	if s[0].OriginRequests != 0 || s[1].OriginRequests != 1 || s[2].OriginRequests != 1 {
		t.Fatal("role counter mismatch")
	}
}
