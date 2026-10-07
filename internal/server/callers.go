// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"time"

	log "github.com/Bugs5382/go-log"

	auditv1 "github.com/Steward-GRC/steward-audit/gen/go/steward/audit/v1"
	"github.com/Steward-GRC/steward-audit/internal/store"
	"github.com/Steward-GRC/steward-audit/internal/workloadauth"
)

// CallerGateway is the gateway's caller name, from the service account
// steward-gateway.
const CallerGateway = "gateway"

// CallerPolicy is audit's per-method allow-list. Only the gateway calls the
// API, on behalf of the signed-in user it names in the request's requester,
// and only on the methods it serves: the three reads and the shred and
// legal-hold methods. ListRecentEvents has no caller (the
// gateway's live tail reads the broker), so it is refused like anything else
// not listed. Events never come through here: they arrive over RabbitMQ.
func CallerPolicy() workloadauth.Policy {
	p := workloadauth.Policy{}
	for _, md := range auditv1.AuditService_ServiceDesc.Methods {
		p["/"+auditv1.AuditService_ServiceDesc.ServiceName+"/"+md.MethodName] = map[string]workloadauth.Access{}
	}
	for _, m := range []string{
		auditv1.AuditService_QueryAuditLog_FullMethodName,
		auditv1.AuditService_ExportAuditSegment_FullMethodName,
		auditv1.AuditService_VerifyAuditChain_FullMethodName,
		auditv1.AuditService_ShredSubject_FullMethodName,
		auditv1.AuditService_CreateLegalHold_FullMethodName,
		auditv1.AuditService_ListLegalHolds_FullMethodName,
		auditv1.AuditService_ReleaseLegalHold_FullMethodName,
	} {
		p[m][CallerGateway] = workloadauth.OnBehalf
	}
	return p
}

// Appender stores a record in the chain.
type Appender interface {
	AppendRecord(ctx context.Context, in store.RecordInput) (*store.Record, error)
}

// AuditDenial records a call the workload-auth interceptor refused as an
// rpc.denied record in the audit tier, appended straight to the chain: audit
// publishing to its own exchange would only queue the record behind the
// consumer for no gain. The actor is the authenticated caller (or
// "unauthenticated"), never a user the call claimed.
func AuditDenial(records Appender, lg log.Logger) workloadauth.DenyHook {
	return func(ctx context.Context, d workloadauth.Denial) {
		caller := d.Caller.Name
		if caller == "" {
			caller = "unauthenticated"
		}
		_, err := records.AppendRecord(ctx, store.RecordInput{
			Tier: "audit", Action: "rpc.denied", ActorUserID: "service:" + caller, Subject: d.Method,
			OccurredAt: time.Now().UTC(),
			Attributes: map[string]string{
				"method": d.Method, "caller": d.Caller.Name, "service_account": d.Caller.ServiceAccount,
				"code": d.Code.String(), "reason": d.Reason,
			},
		})
		if err != nil {
			lg.Ctx(ctx).Error(err, "recording a refused call failed", log.F("method", d.Method), log.F("caller", caller))
		}
	}
}
