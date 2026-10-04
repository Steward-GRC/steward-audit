// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package auditerr

import (
	"context"
	"errors"
	"os"
	"testing"

	apperr "github.com/Bugs5382/go-apperr"
	"github.com/Bugs5382/go-apperr/apperrgrpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestStoreUnavailableRoundTrip(t *testing.T) {
	err := Error(context.Background(), StoreUnavailable("query", errors.New("pq: connection refused at 192.0.2.10")))
	st := status.Convert(err)
	if st.Code() != codes.Internal {
		t.Fatalf("code %v, want Internal", st.Code())
	}
	if st.Message() != "Code 2001: Internal Error" {
		t.Fatalf("an internal cause must never reach the wire, got %q", st.Message())
	}
	info, ok := apperrgrpc.FromError(err)
	if !ok || info.Symbol != "AUDIT_STORE_UNAVAILABLE" || info.Code != 2001 || info.Domain != Domain || info.Metadata["op"] != "query" {
		t.Fatalf("ErrorInfo = %+v, %v", info, ok)
	}
}

func TestUserSafeCodesRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		err    error
		code   codes.Code
		symbol string
		num    int
	}{
		{ExportForbidden(), codes.PermissionDenied, "AUDIT_EXPORT_FORBIDDEN", 2002},
		{GroupScopeDenied(), codes.PermissionDenied, "AUDIT_GROUP_SCOPE_DENIED", 2003},
		{Unauthenticated(), codes.Unauthenticated, "AUDIT_UNAUTHENTICATED", 2004},
		{InvalidPageToken(), codes.InvalidArgument, "AUDIT_INVALID_PAGE_TOKEN", 2005},
		{TailForbidden(), codes.PermissionDenied, "AUDIT_TAIL_FORBIDDEN", 2006},
	} {
		wire := Error(context.Background(), tc.err)
		st := status.Convert(wire)
		entry, _ := Registry().Describe(tc.num)
		if st.Code() != tc.code || st.Message() != entry.Message {
			t.Errorf("%s: %v %q", tc.symbol, st.Code(), st.Message())
		}
		info, _ := apperrgrpc.FromError(wire)
		if info.Symbol != tc.symbol || info.Code != tc.num {
			t.Errorf("%s: ErrorInfo %+v", tc.symbol, info)
		}
	}
}

func TestUncodedErrorsFallBackToInternal(t *testing.T) {
	info, _ := apperrgrpc.FromError(Error(context.Background(), errors.New("boom")))
	if info.Code != CodeInternal || info.Symbol != "AUDIT_INTERNAL" {
		t.Fatalf("ErrorInfo = %+v", info)
	}
}

func TestEveryCodeIsInTheAuditBand(t *testing.T) {
	for _, e := range Entries() {
		if e.Code/1000 != 2 {
			t.Errorf("code %d is outside band 2", e.Code)
		}
		if code, ok := apperr.Code(apperr.Coded(e.Code, nil)); !ok || code != e.Code {
			t.Errorf("code %d does not round-trip", e.Code)
		}
	}
}

// docs/error-codes.md is generated from the registry; keep it current with
// UPDATE_DOCS=1 go test ./internal/auditerr.
func TestErrorCodesDocIsCurrent(t *testing.T) {
	const path = "../../docs/error-codes.md"
	want := Doc()
	if os.Getenv("UPDATE_DOCS") == "1" {
		if err := os.WriteFile(path, []byte(want), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(got) != want {
		t.Fatalf("%s is stale; run UPDATE_DOCS=1 go test ./internal/auditerr", path)
	}
}
