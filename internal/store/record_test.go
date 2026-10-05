// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/Steward-GRC/steward-audit/internal/chain"
	"github.com/Steward-GRC/steward-audit/internal/fixture"
)

func published(actor, subject string) RecordInput {
	return RecordInput{Tier: "audit", Action: fixture.PolicyPublished, ActorUserID: actor,
		Subject: subject, GroupID: fixture.FacilitiesTeam, OccurredAt: time.Now().UTC()}
}

func toVerify(recs []Record) []chain.VerifyRecord {
	out := make([]chain.VerifyRecord, len(recs))
	for i, r := range recs {
		out[i] = r.VerifyRecord()
	}
	return out
}

func TestAppendRecordChainIntegrity(t *testing.T) {
	ctx := context.Background()
	rs := NewRecordStore(newTestDB(t))

	got1, err := rs.AppendRecord(ctx, published(fixture.Bob, fixture.DeskBookingPolicy))
	if err != nil {
		t.Fatalf("AppendRecord 1: %v", err)
	}
	if got1.PrevHash != "" {
		t.Fatalf("first record prev_hash must be empty (genesis), got %q", got1.PrevHash)
	}
	if got1.RecordHash == "" || got1.ID == 0 || got1.RecordUUID == "" {
		t.Fatalf("first record not populated: %+v", got1)
	}

	got2, err := rs.AppendRecord(ctx, RecordInput{Tier: "activity", Action: fixture.PolicyViewed, ActorUserID: fixture.Erin,
		Subject: fixture.DeskBookingPolicy, GroupID: fixture.FacilitiesTeam, OccurredAt: time.Now().UTC()})
	if err != nil {
		t.Fatalf("AppendRecord 2: %v", err)
	}
	if got2.PrevHash != got1.RecordHash {
		t.Fatalf("record 2 prev_hash %q != record 1 hash %q", got2.PrevHash, got1.RecordHash)
	}
	if got2.RecordHash == got1.RecordHash {
		t.Fatal("record 2 hash must differ from record 1 hash")
	}
}

func TestAppendRecordPersistsAllFields(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	rs := NewRecordStore(db)

	retain := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Microsecond)
	in := RecordInput{
		Tier: "audit", Action: "user.consent.recorded", ActorUserID: fixture.Erin, Subject: fixture.UserErin,
		GroupID: fixture.FinanceTeam, OccurredAt: time.Now().UTC().Truncate(time.Microsecond),
		Attributes: map[string]string{"a": "1", "b": "2"}, PIISubjectKey: fixture.ErinKeyAlias,
		PIICiphertext: []byte{0x01, 0x02, 0x03, 0x04}, LegalBasisExempt: true, RetainedUntil: &retain,
	}
	got, err := rs.AppendRecord(ctx, in)
	if err != nil {
		t.Fatalf("AppendRecord: %v", err)
	}

	recs, err := rs.RecordsInRange(ctx, got.ID, got.ID)
	if err != nil || len(recs) != 1 {
		t.Fatalf("readback: %v (%d rows)", err, len(recs))
	}
	r := recs[0]
	if r.Tier != in.Tier || r.Action != in.Action || r.ActorUserID != in.ActorUserID || r.Subject != in.Subject || r.GroupID != in.GroupID {
		t.Fatalf("string fields mismatch: %+v", r)
	}
	if !r.OccurredAt.Equal(in.OccurredAt) {
		t.Fatalf("occurred_at mismatch: got %v want %v", r.OccurredAt, in.OccurredAt)
	}
	if r.PIISubjectKey != in.PIISubjectKey || string(r.PIICiphertext) != string(in.PIICiphertext) {
		t.Fatalf("pii mismatch: %q %x", r.PIISubjectKey, r.PIICiphertext)
	}
	if !r.LegalBasisExempt {
		t.Fatal("legal_basis_exempt should be true")
	}
	if r.RetainedUntil == nil || !r.RetainedUntil.Equal(retain) {
		t.Fatalf("retained_until mismatch: got %v want %v", r.RetainedUntil, retain)
	}
	if r.Attributes["a"] != "1" || r.Attributes["b"] != "2" {
		t.Fatalf("attributes mismatch: %v", r.Attributes)
	}
	if r.PrevHash != "" || r.RecordHash != got.RecordHash {
		t.Fatalf("hash mismatch between insert and readback")
	}
}

func TestAppendRecordOmitsNullablePIIFields(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	rs := NewRecordStore(db)

	got, err := rs.AppendRecord(ctx, published(fixture.Bob, fixture.DeskBookingPolicy))
	if err != nil {
		t.Fatalf("AppendRecord: %v", err)
	}
	var piiKey *string
	var piiCT []byte
	if err := db.Querier().QueryRow(ctx,
		`SELECT pii_subject_key, pii_ciphertext FROM audit_records WHERE id = $1`, got.ID,
	).Scan(&piiKey, &piiCT); err != nil {
		t.Fatalf("readback: %v", err)
	}
	if piiKey != nil || piiCT != nil {
		t.Fatalf("pii columns should be NULL, got %v %x", piiKey, piiCT)
	}
}

func TestListByRangeReturnsInOrder(t *testing.T) {
	ctx := context.Background()
	rs := NewRecordStore(newTestDB(t))

	var ids []int64
	for i := range 5 {
		got, err := rs.AppendRecord(ctx, RecordInput{Tier: "audit", Action: "x", ActorUserID: fixture.Bob,
			Subject: "s", GroupID: "g", OccurredAt: time.Now().UTC()})
		if err != nil {
			t.Fatalf("AppendRecord %d: %v", i, err)
		}
		ids = append(ids, got.ID)
	}

	all, err := rs.RecordsInRange(ctx, ids[0], ids[4])
	if err != nil {
		t.Fatalf("RecordsInRange full: %v", err)
	}
	if len(all) != 5 {
		t.Fatalf("expected 5 rows, got %d", len(all))
	}
	for i := 0; i < len(all)-1; i++ {
		if all[i].ID >= all[i+1].ID {
			t.Fatalf("rows not in ascending id order at i=%d", i)
		}
		if all[i+1].PrevHash != all[i].RecordHash {
			t.Fatalf("chain broken at i=%d", i+1)
		}
	}
	if all[0].PrevHash != "" {
		t.Fatalf("first row prev_hash should be empty, got %q", all[0].PrevHash)
	}

	mid, err := rs.RecordsInRange(ctx, ids[1], ids[3])
	if err != nil {
		t.Fatalf("RecordsInRange mid: %v", err)
	}
	if len(mid) != 3 || mid[0].ID != ids[1] || mid[2].ID != ids[3] {
		t.Fatalf("sub-range mismatch: %d rows", len(mid))
	}
	prev, err := rs.PrecedingHash(ctx, ids[1])
	if err != nil || prev != all[0].RecordHash {
		t.Fatalf("PrecedingHash = %q, %v; want record 1's hash", prev, err)
	}
	if prev, _ := rs.PrecedingHash(ctx, ids[0]); prev != "" {
		t.Fatalf("PrecedingHash of the genesis = %q, want empty", prev)
	}
}

func TestListByRangeEmpty(t *testing.T) {
	rows, err := NewRecordStore(newTestDB(t)).RecordsInRange(context.Background(), 1, 100)
	if err != nil {
		t.Fatalf("RecordsInRange on empty table: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("expected 0 rows on empty table, got %d", len(rows))
	}
}

// Concurrent appenders racing at the genesis leave exactly one genesis record.
func TestAppendRecordConcurrentGenesisRace(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	rs := NewRecordStore(db)

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		wg.Go(func() {
			_, err := rs.AppendRecord(ctx, published(fixture.Bob, fixture.DeskBookingPolicy))
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("serialization conflicts must be retried, got %v", err)
		}
	}
	var genesisCount int
	if err := db.Querier().QueryRow(ctx, `SELECT COUNT(*) FROM audit_records WHERE prev_hash = ''`).Scan(&genesisCount); err != nil {
		t.Fatalf("count genesis: %v", err)
	}
	if genesisCount != 1 {
		t.Fatalf("want one genesis record, got %d", genesisCount)
	}
}

// Under contention every append lands, retried by go-postgres, and the chain
// still verifies end to end.
func TestAppendRecordConcurrentAppendsKeepTheChain(t *testing.T) {
	ctx := context.Background()
	rs := NewRecordStore(newTestDB(t))

	const n = 24
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for range n {
		wg.Go(func() {
			_, err := rs.AppendRecord(ctx, published(fixture.Carol, fixture.ExpenseClaimsPolicy))
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("AppendRecord under contention: %v", err)
		}
	}
	recs, err := rs.RecordsInRange(ctx, 1, 1<<40)
	if err != nil {
		t.Fatalf("RecordsInRange: %v", err)
	}
	if len(recs) != n {
		t.Fatalf("want %d records, got %d", n, len(recs))
	}
	if report := chain.VerifyChain(toVerify(recs), nil); !report.Valid {
		t.Fatalf("chain broken under contention: %v", report.Errors)
	}
}

// Records written with nanosecond times and attributes, then read back, verify:
// the chain commits to the microsecond time Postgres keeps.
func TestAppendRecordVerifyFreshChainWithAttributes(t *testing.T) {
	ctx := context.Background()
	rs := NewRecordStore(newTestDB(t))

	inputs := []RecordInput{
		{Tier: "audit", Action: "user.bootstrap_root", ActorUserID: fixture.Alice, Subject: "user:alice", GroupID: fixture.FacilitiesTeam,
			OccurredAt: time.Now().UTC(), Attributes: map[string]string{"username": fixture.Alice, "source": "setup", "b": "2", "a": "1"}},
		{Tier: "audit", Action: "role.granted", ActorUserID: fixture.Alice, Subject: fixture.UserBob, GroupID: fixture.FacilitiesTeam,
			OccurredAt: time.Now().UTC(), Attributes: map[string]string{"role": "author", "category": "Workplace"}},
		{Tier: "activity", Action: "user.login.success", ActorUserID: fixture.Bob, Subject: fixture.UserBob, GroupID: fixture.FacilitiesTeam,
			OccurredAt: time.Now().UTC(), Attributes: map[string]string{"method": "passkey"}},
		{Tier: "audit", Action: fixture.PolicyPublished, ActorUserID: fixture.Bob, Subject: fixture.DeskBookingPolicy,
			GroupID: fixture.FacilitiesTeam, OccurredAt: time.Now().UTC()},
	}
	var maxID int64
	for i := range inputs {
		got, err := rs.AppendRecord(ctx, inputs[i])
		if err != nil {
			t.Fatalf("AppendRecord %d: %v", i, err)
		}
		maxID = got.ID
	}
	recs, err := rs.RecordsInRange(ctx, 1, maxID)
	if err != nil {
		t.Fatalf("RecordsInRange: %v", err)
	}
	report := chain.VerifyChain(toVerify(recs), nil)
	if !report.Valid {
		t.Fatalf("fresh chain failed verification: %v", report.Errors)
	}
	if report.RecordsChecked != len(inputs) {
		t.Fatalf("RecordsChecked = %d, want %d", report.RecordsChecked, len(inputs))
	}
}

// A direct UPDATE of a stored row is caught on verify.
func TestVerifyDetectsSQLTampering(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	rs := NewRecordStore(db)
	for range 3 {
		if _, err := rs.AppendRecord(ctx, published(fixture.Bob, fixture.DeskBookingPolicy)); err != nil {
			t.Fatalf("AppendRecord: %v", err)
		}
	}
	if _, err := db.Querier().Exec(ctx, `UPDATE audit_records SET actor_user_id = $1 WHERE id = 2`, fixture.Heidi); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	recs, _ := rs.RecordsInRange(ctx, 1, 3)
	if chain.VerifyChain(toVerify(recs), nil).Valid {
		t.Fatal("a tampered row must fail verification")
	}
}

func TestQueryRecordsFiltersAndPages(t *testing.T) {
	ctx := context.Background()
	rs := NewRecordStore(newTestDB(t))
	for _, in := range []RecordInput{
		published(fixture.Bob, fixture.DeskBookingPolicy),
		{Tier: "activity", Action: fixture.PolicyViewed, ActorUserID: fixture.Erin, Subject: fixture.DeskBookingPolicy, GroupID: fixture.FinanceTeam, OccurredAt: time.Now().UTC()},
		published(fixture.Carol, fixture.TravelProcedure),
	} {
		if _, err := rs.AppendRecord(ctx, in); err != nil {
			t.Fatalf("AppendRecord: %v", err)
		}
	}
	got, err := rs.QueryRecords(ctx, QueryFilter{Tier: "audit"})
	if err != nil || len(got) != 2 {
		t.Fatalf("tier filter: %d rows, %v", len(got), err)
	}
	got, _ = rs.QueryRecords(ctx, QueryFilter{GroupID: fixture.FinanceTeam})
	if len(got) != 1 || got[0].ActorUserID != fixture.Erin {
		t.Fatalf("group filter: %+v", got)
	}
	got, _ = rs.QueryRecords(ctx, QueryFilter{Subject: fixture.DeskBookingPolicy, Limit: 1})
	if len(got) != 1 || got[0].ID != 1 {
		t.Fatalf("first page: %+v", got)
	}
	got, _ = rs.QueryRecords(ctx, QueryFilter{Subject: fixture.DeskBookingPolicy, AfterID: 1})
	if len(got) != 1 || got[0].ID != 2 {
		t.Fatalf("second page: %+v", got)
	}
	got, _ = rs.QueryRecords(ctx, QueryFilter{ActorUserID: fixture.Carol})
	if len(got) != 1 || got[0].Subject != fixture.TravelProcedure {
		t.Fatalf("actor filter: %+v", got)
	}
}

func TestListRecentRecordsFilters(t *testing.T) {
	ctx := context.Background()
	rs := NewRecordStore(newTestDB(t))
	old := published(fixture.Bob, fixture.DeskBookingPolicy)
	old.OccurredAt = time.Now().Add(-2 * time.Hour).UTC()
	for _, in := range []RecordInput{old, published(fixture.Bob, fixture.TravelProcedure),
		{Tier: "activity", Action: fixture.PolicyViewed, ActorUserID: fixture.Erin, OccurredAt: time.Now().UTC()}} {
		if _, err := rs.AppendRecord(ctx, in); err != nil {
			t.Fatalf("AppendRecord: %v", err)
		}
	}
	since := time.Now().Add(-time.Hour)
	got, err := rs.ListRecentRecords(ctx, RecentFilter{Since: since})
	if err != nil || len(got) != 2 {
		t.Fatalf("since filter: %d rows, %v", len(got), err)
	}
	got, _ = rs.ListRecentRecords(ctx, RecentFilter{Since: since, Actor: fixture.Erin})
	if len(got) != 1 || got[0].Action != fixture.PolicyViewed {
		t.Fatalf("actor filter: %+v", got)
	}
	got, _ = rs.ListRecentRecords(ctx, RecentFilter{Since: since, EventType: fixture.PolicyPublished})
	if len(got) != 1 || got[0].Subject != fixture.TravelProcedure {
		t.Fatalf("event type filter: %+v", got)
	}
}

func TestHashesAfterBoundsTheBatch(t *testing.T) {
	ctx := context.Background()
	rs := NewRecordStore(newTestDB(t))
	var hashes []string
	for range 5 {
		r, err := rs.AppendRecord(ctx, published(fixture.Bob, fixture.DeskBookingPolicy))
		if err != nil {
			t.Fatalf("AppendRecord: %v", err)
		}
		hashes = append(hashes, r.RecordHash)
	}
	got, maxID, err := rs.HashesAfter(ctx, 1, 3)
	if err != nil {
		t.Fatalf("HashesAfter: %v", err)
	}
	if maxID != 4 || len(got) != 3 || got[0] != hashes[1] || got[2] != hashes[3] {
		t.Fatalf("HashesAfter(1, 3) = %d hashes to %d", len(got), maxID)
	}
	got, maxID, _ = rs.HashesAfter(ctx, 5, 3)
	if len(got) != 0 || maxID != 0 {
		t.Fatalf("nothing after the tip, got %d to %d", len(got), maxID)
	}
}

// Tombstoning clears personal data on activity records only, and the chain
// still verifies because personal data is not part of the hash.
func TestTombstonePIIScopesToActivityTier(t *testing.T) {
	ctx := context.Background()
	rs := NewRecordStore(newTestDB(t))
	key := "subject-key-erin"
	for _, in := range []RecordInput{
		{Tier: "activity", Action: fixture.PolicyViewed, ActorUserID: fixture.Erin, Subject: fixture.UserErin, OccurredAt: time.Now().UTC(), PIISubjectKey: key, PIICiphertext: []byte("ct1")},
		{Tier: "activity", Action: fixture.PolicyViewed, ActorUserID: fixture.Erin, Subject: fixture.UserErin, OccurredAt: time.Now().UTC(), PIISubjectKey: key, PIICiphertext: []byte("ct2")},
		{Tier: "audit", Action: "user.consent.recorded", ActorUserID: fixture.Erin, Subject: fixture.UserErin, OccurredAt: time.Now().UTC(), PIISubjectKey: key, PIICiphertext: []byte("ct3"), LegalBasisExempt: true},
		{Tier: "activity", Action: fixture.PolicyViewed, ActorUserID: fixture.Bob, Subject: fixture.UserBob, OccurredAt: time.Now().UTC(), PIISubjectKey: "subject-key-bob", PIICiphertext: []byte("ct4")},
	} {
		if _, err := rs.AppendRecord(ctx, in); err != nil {
			t.Fatalf("AppendRecord: %v", err)
		}
	}
	n, err := rs.TombstonePII(ctx, key)
	if err != nil || n != 2 {
		t.Fatalf("TombstonePII = %d, %v; want 2", n, err)
	}
	recs, _ := rs.RecordsInRange(ctx, 1, 4)
	if recs[0].PIICiphertext != nil || recs[0].PIISubjectKey != "" || recs[1].PIICiphertext != nil {
		t.Fatal("activity records keep personal data after tombstoning")
	}
	if string(recs[2].PIICiphertext) != "ct3" || string(recs[3].PIICiphertext) != "ct4" {
		t.Fatal("tombstoning touched an audit-tier record or another subject")
	}
	if report := chain.VerifyChain(toVerify(recs), nil); !report.Valid {
		t.Fatalf("tombstoning broke the chain: %v", report.Errors)
	}
}
