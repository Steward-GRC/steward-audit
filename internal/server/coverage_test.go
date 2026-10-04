// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"reflect"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	auditv1 "github.com/Steward-GRC/steward-audit/gen/go/steward/audit/v1"
)

// knownDeferred lists RPCs still served by the generated Unimplemented stub,
// keyed "Service.Method", each with its reason. Empty: every RPC has a handler.
var knownDeferred = map[string]string{}

// A handler that forgets an RPC still compiles, because the embedded stub
// serves it with codes.Unimplemented. Call every unary RPC on a zero-value
// handler and fail on that code. A panic means real handler code ran.
func TestAuditServerImplementsEveryRPC(t *testing.T) {
	iface := reflect.TypeFor[auditv1.AuditServiceServer]()
	zero := reflect.ValueOf(&AuditServer{}).Convert(iface)
	ctxType := reflect.TypeFor[context.Context]()
	errType := reflect.TypeFor[error]()

	invoked := 0
	for i := 0; i < iface.NumMethod(); i++ {
		m := iface.Method(i)
		mt := m.Type
		if mt.NumIn() != 2 || mt.NumOut() != 2 || mt.In(0) != ctxType || mt.In(1).Kind() != reflect.Pointer ||
			mt.Out(0).Kind() != reflect.Pointer || !mt.Out(1).Implements(errType) {
			continue
		}
		invoked++
		key := "AuditService." + m.Name
		method := zero.Method(i)
		t.Run(key, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Logf("%s reached handler code: %v", key, r)
				}
			}()
			out := method.Call([]reflect.Value{reflect.ValueOf(context.Background()), reflect.New(mt.In(1).Elem())})
			err, _ := out[1].Interface().(error)
			if status.Code(err) != codes.Unimplemented {
				return
			}
			if reason, ok := knownDeferred[key]; ok {
				t.Logf("%s deferred: %s", key, reason)
				return
			}
			t.Errorf("%s is served by the Unimplemented stub", key)
		})
	}
	if invoked < 4 {
		t.Fatalf("only %d unary RPCs were checked, want at least 4", invoked)
	}
}
