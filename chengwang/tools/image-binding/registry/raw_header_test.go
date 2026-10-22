package registry

import "testing"

func TestRawHeaderRejectsHiddenDuplicateLength(t *testing.T) {
	for _, raw := range []string{
		"HTTP/1.1 200 OK\nContent-Length: 5\r\nContent-Length: 5\r\nContent-Type: application/octet-stream",
		"HTTP/1.1 200 OK\rContent-Length: 5\r\nContent-Length: 5\r\nContent-Type: application/octet-stream",
		"HTTP/1.1 200 OK\r\nContent-Length: 5\nContent-Length: 5\r\nContent-Type: application/octet-stream",
	} {
		if validRawHeader([]byte(raw)) {
			t.Fatal("non-CRLF header boundary bypassed duplicate detection")
		}
	}
	if !validRawHeader([]byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: application/octet-stream")) {
		t.Fatal("canonical single Content-Length header rejected")
	}
}
