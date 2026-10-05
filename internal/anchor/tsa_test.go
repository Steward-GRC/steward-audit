// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"context"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// tsReply builds a TimeStampResp with the given PKIStatus and no token: enough
// for the client's status check, which is all it verifies.
func tsReply(t *testing.T, status int) []byte {
	t.Helper()
	type pkiStatusInfo struct{ Status int }
	type timeStampResp struct {
		Status pkiStatusInfo
		Token  asn1.RawValue `asn1:"optional"`
	}
	der, err := asn1.Marshal(timeStampResp{Status: pkiStatusInfo{Status: status}})
	if err != nil {
		t.Fatalf("marshal fake TST: %v", err)
	}
	return der
}

func tsaServer(t *testing.T, body []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if got := r.Header.Get("Content-Type"); got != "application/timestamp-query" {
			t.Errorf("unexpected request Content-Type: %q", got)
		}
		w.Header().Set("Content-Type", "application/timestamp-reply")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestTSAClientAnchorsRoot(t *testing.T) {
	srv := tsaServer(t, tsReply(t, 0))
	client := NewTSAClient(srv.URL)
	result, err := client.Anchor(context.Background(), "deadbeef1234")
	if err != nil {
		t.Fatalf("Anchor: %v", err)
	}
	if len(result.RawToken) == 0 {
		t.Fatal("expected non-empty raw token")
	}
	if result.AnchoredAt == "" {
		t.Fatal("expected non-empty AnchoredAt")
	}
	if client.Type() != "rfc3161" {
		t.Fatalf("type: got %q want %q", client.Type(), "rfc3161")
	}
	if client.URL() != srv.URL {
		t.Fatalf("URL mismatch: got %q want %q", client.URL(), srv.URL)
	}
}

func TestTSAClientErrorsOnNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	if _, err := NewTSAClient(srv.URL).Anchor(context.Background(), "deadbeef"); err == nil {
		t.Fatal("expected error from non-200 response, got nil")
	}
}

func TestTSAClientAcceptsGrantedWithMods(t *testing.T) {
	srv := tsaServer(t, tsReply(t, 1))
	if _, err := NewTSAClient(srv.URL).Anchor(context.Background(), "deadbeef"); err != nil {
		t.Fatalf("grantedWithMods must be accepted: %v", err)
	}
}

func TestTSAClientRejectsRefusedStatus(t *testing.T) {
	for _, status := range []int{2, 3, 4, 5} {
		srv := tsaServer(t, tsReply(t, status))
		if _, err := NewTSAClient(srv.URL).Anchor(context.Background(), "deadbeef"); err == nil {
			t.Fatalf("status %d must be refused", status)
		}
	}
}

// A reply that isn't a TimeStampResp is refused, so garbage is never stored as
// an anchor.
func TestTSAClientRejectsUnparseableReply(t *testing.T) {
	srv := tsaServer(t, []byte("<html>not a timestamp</html>"))
	if _, err := NewTSAClient(srv.URL).Anchor(context.Background(), "deadbeef"); err == nil {
		t.Fatal("an unparseable reply must be refused")
	}
}

// The request is a TimeStampReq v1 over SHA-256 of the root's hex text, asking
// for the TSA certificate.
func TestTSAClientRequestShape(t *testing.T) {
	type messageImprint struct {
		HashAlgorithm pkix.AlgorithmIdentifier
		HashedMessage []byte
	}
	type tsReq struct {
		Version        int
		MessageImprint messageImprint
		CertReq        bool `asn1:"optional"`
	}
	var got tsReq
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if _, err := asn1.Unmarshal(body, &got); err != nil {
			t.Errorf("request is not a TimeStampReq: %v", err)
		}
		_, _ = w.Write(tsReply(t, 0))
	}))
	defer srv.Close()

	root := "3f2a9c41"
	if _, err := NewTSAClient(srv.URL).Anchor(context.Background(), root); err != nil {
		t.Fatalf("Anchor: %v", err)
	}
	want := sha256.Sum256([]byte(root))
	if got.Version != 1 || !got.CertReq {
		t.Fatalf("version %d certReq %v, want 1 and true", got.Version, got.CertReq)
	}
	if !got.MessageImprint.HashAlgorithm.Algorithm.Equal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}) {
		t.Fatalf("hash algorithm %v, want SHA-256", got.MessageImprint.HashAlgorithm.Algorithm)
	}
	if string(got.MessageImprint.HashedMessage) != string(want[:]) {
		t.Fatal("hashed message is not SHA-256 of the root")
	}
}
