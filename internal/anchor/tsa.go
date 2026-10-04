// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// maxReplyBytes bounds what is read from a time-stamp authority.
const maxReplyBytes = 1 << 20

var oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}

// ErrNotGranted means the time-stamp authority refused the request.
var ErrNotGranted = errors.New("anchor: time-stamp request not granted")

// TSAClient anchors roots with an RFC 3161 time-stamp authority. It checks
// only the reply's PKIStatus; the token's signature, imprint and certificate
// chain are verified offline from the stored DER.
type TSAClient struct {
	url    string
	client *http.Client
}

// NewTSAClient returns a client for the authority at tsaURL.
func NewTSAClient(tsaURL string) *TSAClient {
	return &TSAClient{url: tsaURL, client: &http.Client{Timeout: 15 * time.Second}}
}

// Type returns "rfc3161".
func (c *TSAClient) Type() string { return "rfc3161" }

// URL returns the authority endpoint.
func (c *TSAClient) URL() string { return c.url }

// Anchor asks the authority to time-stamp SHA-256 of the root's hex text and
// returns the DER TimeStampResp.
func (c *TSAClient) Anchor(ctx context.Context, merkleRoot string) (*AnchorResult, error) {
	digest := sha256.Sum256([]byte(merkleRoot))
	reqDER, err := buildTSReq(digest[:])
	if err != nil {
		return nil, fmt.Errorf("anchor: build TimeStampReq: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(reqDER))
	if err != nil {
		return nil, fmt.Errorf("anchor: %w", err)
	}
	req.Header.Set("Content-Type", "application/timestamp-query")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("anchor: TSA POST: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("anchor: TSA returned HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxReplyBytes))
	if err != nil {
		return nil, fmt.Errorf("anchor: read TSA reply: %w", err)
	}
	if err := checkTSRespStatus(raw); err != nil {
		return nil, err
	}
	return &AnchorResult{RawToken: raw, AnchoredAt: time.Now().UTC().Format(time.RFC3339Nano)}, nil
}

func buildTSReq(digest []byte) ([]byte, error) {
	type messageImprint struct {
		HashAlgorithm pkix.AlgorithmIdentifier
		HashedMessage []byte
	}
	type tsReq struct {
		Version        int
		MessageImprint messageImprint
		CertReq        bool `asn1:"optional"`
	}
	return asn1.Marshal(tsReq{
		Version:        1,
		MessageImprint: messageImprint{HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidSHA256}, HashedMessage: digest},
		CertReq:        true,
	})
}

type pkiStatusInfo struct{ Status int }

type tsResp struct {
	Status pkiStatusInfo
	Token  asn1.RawValue `asn1:"optional"`
}

// checkTSRespStatus accepts granted (0) and grantedWithMods (1). A reply that
// doesn't parse as a TimeStampResp is refused.
func checkTSRespStatus(der []byte) error {
	var resp tsResp
	if _, err := asn1.Unmarshal(der, &resp); err != nil {
		return fmt.Errorf("anchor: reply is not a TimeStampResp: %w", err)
	}
	if resp.Status.Status != 0 && resp.Status.Status != 1 {
		return fmt.Errorf("%w: PKIStatus %d", ErrNotGranted, resp.Status.Status)
	}
	return nil
}
