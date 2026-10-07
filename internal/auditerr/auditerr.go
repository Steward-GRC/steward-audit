// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Package auditerr holds the audit service's coded errors (band 2) and turns
// them into gRPC statuses through go-apperr.
package auditerr

import (
	"context"
	"errors"
	"fmt"
	"sync"

	apperr "github.com/Bugs5382/go-apperr"
	"github.com/Bugs5382/go-apperr/apperrgrpc"
	log "github.com/Bugs5382/go-log"
)

// Domain is the ErrorInfo domain every audit error carries.
const Domain = "audit"

// The audit service's codes.
const (
	CodeInternal         = 2000
	CodeStoreUnavailable = 2001
	CodeExportForbidden  = 2002
	CodeGroupScopeDenied = 2003
	CodeUnauthenticated  = 2004
	CodeInvalidPageToken = 2005
	CodeTailForbidden    = 2006
	CodeVerifyForbidden  = 2007
	CodeManageForbidden  = 2008
	CodeInvalidArgument  = 2009
	CodeHoldNotFound     = 2010
	CodeShredIncomplete  = 2011
)

// Entries returns the registry entries.
func Entries() []apperr.Entry {
	return []apperr.Entry{
		{Code: CodeInternal, Symbol: "AUDIT_INTERNAL", Category: apperr.CategoryInternal,
			Title: "audit", Cause: "an uncoded failure inside the audit service"},
		{Code: CodeStoreUnavailable, Symbol: "AUDIT_STORE_UNAVAILABLE", Category: apperr.CategoryInternal,
			Title: "audit store", Cause: "an audit store read failed; the op metadata names it, the cause is only logged"},
		{Code: CodeExportForbidden, Symbol: "AUDIT_EXPORT_FORBIDDEN", Category: apperr.CategoryPermissionDenied,
			Title: "audit export", Cause: "a caller without audit.read asked for a raw segment",
			UserSafe: true, Message: "You don't have permission to export raw audit segments. Use the audit log query, which is scoped to the groups you manage."},
		{Code: CodeGroupScopeDenied, Symbol: "AUDIT_GROUP_SCOPE_DENIED", Category: apperr.CategoryPermissionDenied,
			Title: "audit query", Cause: "a caller without audit.read asked for a group it doesn't manage, or for every group",
			UserSafe: true, Message: "You can only view audit records for the groups you manage."},
		{Code: CodeUnauthenticated, Symbol: "AUDIT_UNAUTHENTICATED", Category: apperr.CategoryUnauthenticated,
			Title: "audit", Cause: "the request carried no requester, or one with an empty user id",
			UserSafe: true, Message: "Sign in to view the audit log."},
		{Code: CodeInvalidPageToken, Symbol: "AUDIT_INVALID_PAGE_TOKEN", Category: apperr.CategoryInvalid,
			Title: "audit query", Cause: "the page token is not one this service issued",
			UserSafe: true, Message: "That page of the audit log is no longer valid. Start the search again."},
		{Code: CodeTailForbidden, Symbol: "AUDIT_TAIL_FORBIDDEN", Category: apperr.CategoryPermissionDenied,
			Title: "audit tail", Cause: "the caller has neither audit.read nor a group it manages",
			UserSafe: true, Message: "You don't have permission to follow recent audit events."},
		{Code: CodeVerifyForbidden, Symbol: "AUDIT_VERIFY_FORBIDDEN", Category: apperr.CategoryPermissionDenied,
			Title: "audit verify", Cause: "the caller has neither audit.read nor a group it manages",
			UserSafe: true, Message: "You don't have permission to verify the audit log."},
		{Code: CodeManageForbidden, Symbol: "AUDIT_MANAGE_FORBIDDEN", Category: apperr.CategoryPermissionDenied,
			Title: "audit retention", Cause: "a caller without compliance.manage asked to shred a subject or manage legal holds",
			UserSafe: true, Message: "You don't have permission to shred personal data or manage legal holds."},
		{Code: CodeInvalidArgument, Symbol: "AUDIT_INVALID_ARGUMENT", Category: apperr.CategoryInvalid,
			Title: "audit retention", Cause: "a required field (the subject key, the reason or the hold id) was empty",
			UserSafe: true, Message: "A required field is missing. Give a subject and a reason."},
		{Code: CodeHoldNotFound, Symbol: "AUDIT_HOLD_NOT_FOUND", Category: apperr.CategoryNotFound,
			Title: "legal hold", Cause: "no legal hold in force has that id; it may already be released",
			UserSafe: true, Message: "That legal hold doesn't exist or is already released."},
		{Code: CodeShredIncomplete, Symbol: "AUDIT_SHRED_INCOMPLETE", Category: apperr.CategoryInternal,
			Title: "crypto-shred", Cause: "the subject's key is destroyed but clearing its records or writing the shred record failed; the cause is only logged",
			UserSafe: true, Message: "The personal data is unreadable, but the shred didn't finish. Run it again."},
	}
}

var (
	regOnce sync.Once
	reg     *apperr.Registry
)

// Registry returns the service registry. Coded errors are logged through
// go-log with the trace of the request they failed.
func Registry() *apperr.Registry {
	regOnce.Do(func() {
		r, err := apperr.NewRegistry(Entries(), apperr.WithService(2), apperr.WithCodeDigits(4),
			apperr.WithLogger(logSink{log.NewLogger("audit")}))
		if err != nil {
			panic(err)
		}
		reg = r
	})
	return reg
}

// Error turns err into the gRPC error a handler returns.
func Error(ctx context.Context, err error) error {
	return apperrgrpc.Error(ctx, Registry(), err, CodeInternal, Domain)
}

// Doc is the Markdown body of docs/error-codes.md.
func Doc() string {
	return "# Error codes\n\nEvery gRPC error from the audit service carries an `ErrorInfo` with the symbol as its\n" +
		"reason, the domain `" + Domain + "` and the code in `codeNum`. Only user-safe messages reach the\n" +
		"caller; every other code is sent as `Code N: Internal Error`.\n\n" + Registry().Markdown()
}

// StoreUnavailable codes a failed store read; op names the read.
func StoreUnavailable(op string, cause error) error {
	return apperr.WithMeta(apperr.Coded(CodeStoreUnavailable, cause), apperr.Meta("op", op))
}

var (
	errExportForbidden  = errors.New("audit: export forbidden")
	errGroupScope       = errors.New("audit: outside the caller's group")
	errUnauthenticated  = errors.New("audit: no requester")
	errInvalidPageToken = errors.New("audit: invalid page token")
	errTailForbidden    = errors.New("audit: tail forbidden")
	errVerifyForbidden  = errors.New("audit: verify forbidden")
	errManageForbidden  = errors.New("audit: retention management forbidden")
)

// ExportForbidden codes a refused export.
func ExportForbidden() error { return apperr.Coded(CodeExportForbidden, errExportForbidden) }

// GroupScopeDenied codes a query outside the groups the caller manages.
func GroupScopeDenied() error { return apperr.Coded(CodeGroupScopeDenied, errGroupScope) }

// Unauthenticated codes a request without a requester.
func Unauthenticated() error { return apperr.Coded(CodeUnauthenticated, errUnauthenticated) }

// InvalidPageToken codes a page token that doesn't parse.
func InvalidPageToken() error { return apperr.Coded(CodeInvalidPageToken, errInvalidPageToken) }

// TailForbidden codes a refused tail.
func TailForbidden() error { return apperr.Coded(CodeTailForbidden, errTailForbidden) }

// VerifyForbidden codes a refused verify.
func VerifyForbidden() error { return apperr.Coded(CodeVerifyForbidden, errVerifyForbidden) }

// ManageForbidden codes a refused shred or legal-hold call.
func ManageForbidden() error { return apperr.Coded(CodeManageForbidden, errManageForbidden) }

// InvalidArgument codes a missing required field; field names it.
func InvalidArgument(field string) error {
	return apperr.WithMeta(apperr.Coded(CodeInvalidArgument, fmt.Errorf("audit: %s is required", field)), apperr.Meta("field", field))
}

// HoldNotFound codes an unknown or released hold.
func HoldNotFound(cause error) error { return apperr.Coded(CodeHoldNotFound, cause) }

// ShredIncomplete codes a shred that destroyed the key but didn't finish.
func ShredIncomplete(cause error) error { return apperr.Coded(CodeShredIncomplete, cause) }

type logSink struct{ l log.Logger }

func (s logSink) LogCoded(ctx context.Context, code int, err error) {
	s.l.Ctx(ctx).Debug("coded error", log.F("code", code), log.F("error", err.Error()))
}
