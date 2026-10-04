// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package shred

import (
	"context"
	"errors"
	"testing"

	"github.com/Steward-GRC/steward-audit/internal/fixture"
	"github.com/Steward-GRC/steward-audit/internal/kms"
	"github.com/Steward-GRC/steward-audit/internal/store"
)

type fakeKMS struct {
	erased    map[string]bool
	failKey   string
	deleteErr error
}

func newFakeKMS() *fakeKMS { return &fakeKMS{erased: make(map[string]bool)} }

func (f *fakeKMS) Delete(_ context.Context, alias string) error {
	if f.deleteErr != nil && f.failKey == alias {
		return f.deleteErr
	}
	f.erased[alias] = true
	return nil
}

type fakeTombstoner struct {
	tombstoned   map[string]int
	rowsToReturn int
	failKey      string
	tombstoneErr error
}

func newFakeTombstoner(rows int) *fakeTombstoner {
	return &fakeTombstoner{tombstoned: make(map[string]int), rowsToReturn: rows}
}

func (f *fakeTombstoner) TombstonePII(_ context.Context, subjectKey string) (int, error) {
	if f.tombstoneErr != nil && f.failKey == subjectKey {
		return 0, f.tombstoneErr
	}
	f.tombstoned[subjectKey] = f.rowsToReturn
	return f.rowsToReturn, nil
}

type fakeAppender struct {
	appended  []store.RecordInput
	appendErr error
}

func (f *fakeAppender) AppendRecord(_ context.Context, in store.RecordInput) (*store.Record, error) {
	if f.appendErr != nil {
		return nil, f.appendErr
	}
	f.appended = append(f.appended, in)
	return &store.Record{ID: int64(len(f.appended)), RecordInput: in}, nil
}

func TestShredSubjectHappyPath(t *testing.T) {
	k := newFakeKMS()
	tb := newFakeTombstoner(3)
	ap := &fakeAppender{}
	res, err := NewCryptoShredService(k, tb, ap).ShredSubject(context.Background(), fixture.UserErin, "erasure-request", fixture.Grace)
	if err != nil {
		t.Fatalf("ShredSubject: %v", err)
	}
	if !k.erased[fixture.UserErin] {
		t.Fatal("expected the subject's key to be deleted")
	}
	if tb.tombstoned[fixture.UserErin] != 3 || res.RowsTombstoned != 3 {
		t.Fatalf("expected 3 activity rows tombstoned, got %d", res.RowsTombstoned)
	}
	if len(ap.appended) != 1 {
		t.Fatalf("expected exactly 1 meta-audit record, got %d", len(ap.appended))
	}
	meta := ap.appended[0]
	if meta.Action != "subject.shredded" || meta.Tier != "audit" || !meta.LegalBasisExempt {
		t.Errorf("meta record shape: %+v", meta)
	}
	if meta.ActorUserID != fixture.Grace || meta.Subject != fixture.UserErin {
		t.Errorf("meta actor/subject: %q %q", meta.ActorUserID, meta.Subject)
	}
	if meta.Attributes["reason"] != "erasure-request" || meta.Attributes["rows_tombstoned"] != "3" {
		t.Errorf("meta attributes: %v", meta.Attributes)
	}
	if meta.OccurredAt.IsZero() {
		t.Error("the meta record must carry the time of the shred")
	}
	if res.MetaRecordID != 1 || res.SubjectKey != fixture.UserErin {
		t.Errorf("result: %+v", res)
	}
}

func TestShredSubjectRejectsEmptyKey(t *testing.T) {
	k := newFakeKMS()
	tb := newFakeTombstoner(0)
	ap := &fakeAppender{}
	_, err := NewCryptoShredService(k, tb, ap).ShredSubject(context.Background(), "", "erasure-request", fixture.Grace)
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected ErrInvalidRequest for empty subjectKey, got %v", err)
	}
	if len(k.erased) != 0 || len(tb.tombstoned) != 0 || len(ap.appended) != 0 {
		t.Error("nothing may run when validation fails")
	}
}

func TestShredSubjectRejectsEmptyReason(t *testing.T) {
	svc := NewCryptoShredService(newFakeKMS(), newFakeTombstoner(0), &fakeAppender{})
	if _, err := svc.ShredSubject(context.Background(), fixture.UserBob, "", fixture.Grace); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected ErrInvalidRequest for empty reason, got %v", err)
	}
}

func TestShredSubjectRejectsEmptyActor(t *testing.T) {
	svc := NewCryptoShredService(newFakeKMS(), newFakeTombstoner(0), &fakeAppender{})
	if _, err := svc.ShredSubject(context.Background(), fixture.UserBob, "erasure-request", ""); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected ErrInvalidRequest for empty actor, got %v", err)
	}
}

// If the key can't be deleted nothing is tombstoned: the database would claim
// an erasure while the ciphertext could still be decrypted.
func TestShredSubjectKMSDeleteFailureAborts(t *testing.T) {
	k := newFakeKMS()
	k.failKey = fixture.UserBob
	k.deleteErr = errors.New("kms: unreachable")
	tb := newFakeTombstoner(0)
	ap := &fakeAppender{}
	if _, err := NewCryptoShredService(k, tb, ap).ShredSubject(context.Background(), fixture.UserBob, "erasure-request", fixture.Grace); err == nil {
		t.Fatal("expected error when KMS Delete fails")
	}
	if len(tb.tombstoned) != 0 || len(ap.appended) != 0 {
		t.Error("tombstone and meta-audit must not run if the key delete failed")
	}
}

// After the key is gone a tombstone failure is reported as a partial shred,
// and no "subject.shredded" record claims it finished.
func TestShredSubjectTombstoneFailurePropagates(t *testing.T) {
	k := newFakeKMS()
	tb := newFakeTombstoner(0)
	tb.failKey = fixture.UserBob
	tb.tombstoneErr = errors.New("db: connection reset")
	ap := &fakeAppender{}
	_, err := NewCryptoShredService(k, tb, ap).ShredSubject(context.Background(), fixture.UserBob, "erasure-request", fixture.Grace)
	if !errors.Is(err, ErrPartialShred) {
		t.Fatalf("expected ErrPartialShred, got %v", err)
	}
	if !k.erased[fixture.UserBob] {
		t.Error("the key must already be deleted (key first)")
	}
	if len(ap.appended) != 0 {
		t.Errorf("meta-audit must not be written on partial failure (got %d)", len(ap.appended))
	}
}

func TestShredSubjectMetaAuditFailureSurfaces(t *testing.T) {
	ap := &fakeAppender{appendErr: errors.New("db: append failed")}
	_, err := NewCryptoShredService(newFakeKMS(), newFakeTombstoner(2), ap).ShredSubject(context.Background(), fixture.UserBob, "erasure-request", fixture.Grace)
	if !errors.Is(err, ErrPartialShred) {
		t.Fatalf("expected ErrPartialShred when the meta-audit append fails, got %v", err)
	}
}

func TestKMSKeyProviderSatisfiesKeyEraser(t *testing.T) {
	var _ KeyEraser = (kms.KeyProvider)(nil)
}

func TestRecordStoreSatisfiesTheShredStores(t *testing.T) {
	var _ PIITombstoner = (*store.RecordStore)(nil)
	var _ MetaAuditAppender = (*store.RecordStore)(nil)
}
