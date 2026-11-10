// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Bugs5382/go-buildinfo/health"
	log "github.com/Bugs5382/go-log"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	reflectionpb "google.golang.org/grpc/reflection/grpc_reflection_v1"
	"google.golang.org/grpc/status"

	workloadidentity "github.com/Bugs5382/go-workload-identity"
	auditv1 "github.com/Steward-GRC/steward-audit/gen/go/steward/audit/v1"
	"github.com/Steward-GRC/steward-audit/internal/config"
	"github.com/Steward-GRC/steward-audit/internal/readiness"
	"github.com/Steward-GRC/steward-audit/internal/store"
)

const testNS = "steward"

// localIssuer is an OIDC issuer on a local TLS test server: discovery and a
// JWKS with one P-256 key generated in the test.
type localIssuer struct {
	url, caFile string
	key         *ecdsa.PrivateKey
	// jwksStatus, when set, is the status the JWKS endpoint answers instead
	// of the key set.
	jwksStatus atomic.Int32
}

func newLocalIssuer(t *testing.T) *localIssuer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	iss := &localIssuer{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": iss.url, "jwks_uri": iss.url + "/openid/v1/jwks"})
	})
	mux.HandleFunc("/openid/v1/jwks", func(w http.ResponseWriter, _ *http.Request) {
		if code := iss.jwksStatus.Load(); code != 0 {
			http.Error(w, http.StatusText(int(code)), int(code))
			return
		}
		pub, err := key.PublicKey.ECDH()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		raw := pub.Bytes()
		b64 := base64.RawURLEncoding.EncodeToString
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "EC", "kid": "k1", "use": "sig", "crv": "P-256", "x": b64(raw[1:33]), "y": b64(raw[33:]),
		}}})
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	iss.url = srv.URL
	iss.caFile = filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(iss.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600))
	return iss
}

// tokenAt signs a token for sa that was issued at iat and expires an hour later.
func (i *localIssuer) tokenAt(t *testing.T, sa, audience string, iat time.Time) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": i.url, "aud": []string{audience}, "sub": "system:serviceaccount:" + testNS + ":" + sa,
		"iat": iat.Unix(), "nbf": iat.Unix(), "exp": iat.Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = "k1"
	s, err := tok.SignedString(i.key)
	require.NoError(t, err)
	return s
}

func (i *localIssuer) token(t *testing.T, sa, audience string) string {
	return i.tokenAt(t, sa, audience, time.Now())
}

// serve runs Serve with opts and the real AuditService handlers on fs.
func serve(t *testing.T, opts Options, fs *fakeQueryStore) (*grpc.ClientConn, func()) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, lis, log.Nop(), opts, func(s *grpc.Server) { auditv1.RegisterAuditServiceServer(s, NewAuditServer(fs)) })
	}()
	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	return conn, func() {
		_ = conn.Close()
		cancel()
		require.NoError(t, <-done)
	}
}

// authServe serves with workload auth on and the real caller policy:
// steward-gateway and steward-reporting hold valid identities, but only the
// gateway is on any method. Refusals are recorded in fs's chain.
func authServe(t *testing.T) (*localIssuer, *grpc.ClientConn, *fakeQueryStore, func()) {
	t.Helper()
	iss := newLocalIssuer(t)
	v, err := workloadidentity.NewVerifier(config.StewardWorkload(workloadidentity.Config{
		Issuer: iss.url, CAFile: iss.caFile,
		AllowedServiceAccounts: []string{testNS + "/steward-gateway", testNS + "/steward-reporting"},
	}), log.Nop())
	require.NoError(t, err)
	require.NoError(t, v.Refresh(context.Background()))
	fs := &fakeQueryStore{records: []store.Record{seedRecord(time.Now().UTC())}}
	conn, stop := serve(t, Options{Auth: &Auth{
		Verifier: v, Policy: CallerPolicy(),
		Options: []workloadidentity.Option{workloadidentity.WithDenyHook(AuditDenial(fs, log.Nop()))},
	}}, fs)
	return iss, conn, fs, stop
}

func bearerCtx(tok string) context.Context {
	return metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+tok)
}

func callQuery(conn *grpc.ClientConn, ctx context.Context) codes.Code {
	_, err := auditv1.NewAuditServiceClient(conn).QueryAuditLog(ctx, &auditv1.QueryAuditLogRequest{PageSize: 10, Requester: auditor})
	return status.Code(err)
}

func TestWorkloadAuthLetsTheGatewayCallItsMethods(t *testing.T) {
	iss, conn, fs, stop := authServe(t)
	defer stop()
	ctx := bearerCtx(iss.token(t, "steward-gateway", "steward"))
	c := auditv1.NewAuditServiceClient(conn)
	res, err := c.QueryAuditLog(ctx, &auditv1.QueryAuditLogRequest{PageSize: 10, Requester: auditor})
	require.NoError(t, err)
	require.Len(t, res.GetRecords(), 1)
	_, err = c.ExportAuditSegment(ctx, &auditv1.ExportAuditSegmentRequest{FromRecordId: 1, ToRecordId: 1, Requester: auditor})
	require.NoError(t, err)
	_, err = c.VerifyAuditChain(ctx, &auditv1.VerifyAuditChainRequest{FromRecordId: 1, ToRecordId: 1, Requester: auditor})
	require.NoError(t, err)
	for _, in := range fs.appended {
		require.NotEqual(t, "rpc.denied", in.Action, "an allowed call records no refusal")
	}
}

func TestWorkloadAuthRefusesAMissingOrInvalidToken(t *testing.T) {
	iss, conn, _, stop := authServe(t)
	defer stop()
	require.Equal(t, codes.Unauthenticated, callQuery(conn, context.Background()), "no token")
	require.Equal(t, codes.Unauthenticated, callQuery(conn, bearerCtx("not-a-jwt")), "a malformed token")
	require.Equal(t, codes.Unauthenticated, callQuery(conn, bearerCtx(iss.token(t, "steward-gateway", "other"))), "another audience")
	other := newLocalIssuer(t)
	require.Equal(t, codes.Unauthenticated, callQuery(conn, bearerCtx(other.token(t, "steward-gateway", "steward"))), "another issuer")
	expired := iss.tokenAt(t, "steward-gateway", "steward", time.Now().Add(-2*time.Hour))
	require.Equal(t, codes.Unauthenticated, callQuery(conn, bearerCtx(expired)), "an expired token")
}

func TestWorkloadAuthRefusesAValidTokenFromAnUnlistedCaller(t *testing.T) {
	iss, conn, _, stop := authServe(t)
	defer stop()
	require.Equal(t, codes.PermissionDenied, callQuery(conn, bearerCtx(iss.token(t, "steward-reporting", "steward"))),
		"a verified identity the method doesn't list")
	require.Equal(t, codes.Unauthenticated, callQuery(conn, bearerCtx(iss.token(t, "steward-ai", "steward"))),
		"a valid token from a service account outside WORKLOAD_ALLOWED_SERVICEACCOUNTS")
}

func TestWorkloadAuthRefusesAMethodNoCallerUses(t *testing.T) {
	iss, conn, _, stop := authServe(t)
	defer stop()
	_, err := auditv1.NewAuditServiceClient(conn).ListRecentEvents(bearerCtx(iss.token(t, "steward-gateway", "steward")),
		&auditv1.ListRecentEventsRequest{Requester: auditor})
	require.Equal(t, codes.PermissionDenied, status.Code(err), "the gateway tails over RabbitMQ, so no caller is on ListRecentEvents")
}

func TestWorkloadAuthRecordsEachRefusalInTheChain(t *testing.T) {
	iss, conn, fs, stop := authServe(t)
	defer stop()
	require.Equal(t, codes.Unauthenticated, callQuery(conn, context.Background()))
	require.Equal(t, codes.PermissionDenied, callQuery(conn, bearerCtx(iss.token(t, "steward-reporting", "steward"))))
	require.Len(t, fs.appended, 2)
	anon, rep := fs.appended[0], fs.appended[1]
	require.Equal(t, "audit", anon.Tier)
	require.Equal(t, "rpc.denied", anon.Action)
	require.Equal(t, "service:unauthenticated", anon.ActorUserID)
	require.Equal(t, auditv1.AuditService_QueryAuditLog_FullMethodName, anon.Subject)
	require.Equal(t, codes.Unauthenticated.String(), anon.Attributes["code"])
	require.Equal(t, workloadidentity.ReasonNoToken, anon.Attributes["reason"])
	require.False(t, anon.OccurredAt.IsZero())
	require.Equal(t, "service:reporting", rep.ActorUserID)
	require.Equal(t, testNS+"/steward-reporting", rep.Attributes["service_account"])
	require.Equal(t, workloadidentity.ReasonMethodNotAllowed, rep.Attributes["reason"])
}

func TestWorkloadAuthLeavesHealthAndReflectionOpen(t *testing.T) {
	_, conn, _, stop := authServe(t)
	defer stop()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hc, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
	require.NoError(t, err)
	require.Equal(t, healthpb.HealthCheckResponse_SERVING, hc.GetStatus())
	rs, err := reflectionpb.NewServerReflectionClient(conn).ServerReflectionInfo(ctx)
	require.NoError(t, err)
	require.NoError(t, rs.Send(&reflectionpb.ServerReflectionRequest{MessageRequest: &reflectionpb.ServerReflectionRequest_ListServices{}}))
	res, err := rs.Recv()
	require.NoError(t, err)
	require.NotEmpty(t, res.GetListServicesResponse().GetService())
}

func TestWorkloadAuthDisabledLetsCallsThrough(t *testing.T) {
	conn, stop := serve(t, Options{}, &fakeQueryStore{records: []store.Record{seedRecord(time.Now().UTC())}})
	defer stop()
	require.Equal(t, codes.OK, callQuery(conn, context.Background()), "WORKLOAD_AUTH=disabled serves a call with no token")
}

type upDB struct{}

func (upDB) Ping(context.Context) error                    { return nil }
func (upDB) ServerVersion(context.Context) (string, error) { return "16.4", nil }

type upBroker struct{}

func (upBroker) Healthy() bool { return true }

// The issuer refusing the JWKS fetch (as an API server does for a bearer with
// the wrong audience) must never leave the verifier inert: a valid-looking
// token is refused, and readiness drains the pod on both probes.
func TestWorkloadAuthFailsClosedWhileTheJWKSIsRefused(t *testing.T) {
	iss := newLocalIssuer(t)
	iss.jwksStatus.Store(http.StatusUnauthorized)
	v, err := workloadidentity.NewVerifier(config.StewardWorkload(workloadidentity.Config{
		Issuer: iss.url, CAFile: iss.caFile,
		AllowedServiceAccounts: []string{testNS + "/steward-gateway"},
	}), log.Nop())
	require.NoError(t, err)
	require.Error(t, v.Refresh(context.Background()), "a 401 from the JWKS is a failed refresh")

	checker, err := readiness.New(readiness.Deps{Postgres: upDB{}, Broker: upBroker{},
		JWKS: readiness.RecheckEvery(v.Refresh, time.Minute, time.Now)}, health.WithTTL(time.Millisecond))
	require.NoError(t, err)
	fs := &fakeQueryStore{records: []store.Record{seedRecord(time.Now().UTC())}}
	conn, stop := serve(t, Options{Checker: checker, CheckInterval: 20 * time.Millisecond, Auth: &Auth{
		Verifier: v, Policy: CallerPolicy(),
	}}, fs)
	defer stop()

	require.Equal(t, codes.Unavailable, callQuery(conn, bearerCtx(iss.token(t, "steward-gateway", "steward"))))
	require.Empty(t, fs.lastQuery, "the handler never ran without a verified caller")

	hc := healthpb.NewHealthClient(conn)
	for _, svc := range []string{"", ReadinessService} {
		r, err := hc.Check(context.Background(), &healthpb.HealthCheckRequest{Service: svc})
		require.NoError(t, err)
		require.Equal(t, healthpb.HealthCheckResponse_NOT_SERVING, r.GetStatus(), "service %q", svc)
	}
	rep := checker.Report(context.Background())
	require.False(t, rep.Ready)
	var jwks *health.DependencyReport
	for i := range rep.Dependencies {
		if rep.Dependencies[i].Name == readiness.JWKS {
			jwks = &rep.Dependencies[i]
		}
	}
	require.NotNil(t, jwks, "the key set is listed in the readiness report")
	require.True(t, jwks.Required)
	require.Equal(t, health.StateDown, jwks.State)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ServeProbes(ctx, lis, checker) }()
	defer func() { cancel(); require.NoError(t, <-done) }()
	res, err := http.Get("http://" + lis.Addr().String() + "/readyz")
	require.NoError(t, err)
	_ = res.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, res.StatusCode)
	res, err = http.Get("http://" + lis.Addr().String() + "/livez")
	require.NoError(t, err)
	_ = res.Body.Close()
	require.Equal(t, http.StatusOK, res.StatusCode, "liveness never follows a dependency")
}

// The policy is the whole allow-list: the gateway, on behalf of the signed-in
// user it names in the requester, on the three reads and the four retention
// methods it calls; nobody on anything else.
func TestCallerPolicyListsOnlyTheGatewaysMethods(t *testing.T) {
	p := CallerPolicy()
	want := map[string]map[string]workloadidentity.Access{
		auditv1.AuditService_QueryAuditLog_FullMethodName:      {CallerGateway: workloadidentity.OnBehalf},
		auditv1.AuditService_ExportAuditSegment_FullMethodName: {CallerGateway: workloadidentity.OnBehalf},
		auditv1.AuditService_VerifyAuditChain_FullMethodName:   {CallerGateway: workloadidentity.OnBehalf},
		auditv1.AuditService_ShredSubject_FullMethodName:       {CallerGateway: workloadidentity.OnBehalf},
		auditv1.AuditService_CreateLegalHold_FullMethodName:    {CallerGateway: workloadidentity.OnBehalf},
		auditv1.AuditService_ListLegalHolds_FullMethodName:     {CallerGateway: workloadidentity.OnBehalf},
		auditv1.AuditService_ReleaseLegalHold_FullMethodName:   {CallerGateway: workloadidentity.OnBehalf},
	}
	got := map[string]map[string]workloadidentity.Access{}
	for m, callers := range p {
		if len(callers) > 0 {
			got[m] = callers
		}
	}
	require.Equal(t, want, got)
	for _, md := range auditv1.AuditService_ServiceDesc.Methods {
		m := "/" + auditv1.AuditService_ServiceDesc.ServiceName + "/" + md.MethodName
		for _, caller := range []string{"reporting", "core", "ai", "migrate"} {
			_, ok := p.Lookup(m, caller)
			require.False(t, ok, "%s on %s", caller, m)
		}
	}
	_, ok := p.Lookup(auditv1.AuditService_ListRecentEvents_FullMethodName, CallerGateway)
	require.False(t, ok)
}
