// Package attestation provides in-toto attestation creation and signing.
package attestation

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/aflock-ai/aflock/internal/identity"
	"github.com/aflock-ai/aflock/pkg/aflock"
)

const (
	// PayloadType is the DSSE payload type for in-toto statements.
	PayloadType = "application/vnd.in-toto+json"
	// StatementType is the in-toto statement type.
	StatementType = "https://in-toto.io/Statement/v1"
	// PredicateTypeAflockAction is the predicate type for aflock actions.
	PredicateTypeAflockAction = "https://aflock.ai/attestations/action/v0.1"
)

// Signer creates and signs attestations.
type Signer struct {
	spireClient *identity.SpireClient
	identity    *identity.Identity
}

// NewSigner creates a new attestation signer.
// If spireSocketPath is empty, uses default SPIRE socket or falls back to local signing.
func NewSigner(spireSocketPath string) *Signer {
	return &Signer{
		spireClient: identity.NewSpireClient(spireSocketPath),
	}
}

// Initialize connects to SPIRE and fetches identity.
func (s *Signer) Initialize(ctx context.Context) error {
	if err := s.spireClient.Connect(ctx); err != nil {
		return fmt.Errorf("connect to SPIRE: %w", err)
	}

	id, err := s.spireClient.GetIdentity(ctx)
	if err != nil {
		return fmt.Errorf("get identity: %w", err)
	}

	s.identity = id
	return nil
}

// Close releases resources.
func (s *Signer) Close() error {
	if s.spireClient != nil {
		return s.spireClient.Close()
	}
	return nil
}

// Statement represents an in-toto statement.
type Statement struct {
	Type          string      `json:"_type"`
	Subject       []Subject   `json:"subject"`
	PredicateType string      `json:"predicateType"`
	Predicate     interface{} `json:"predicate"`
}

// Subject represents an in-toto subject.
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// ActionPredicate is the predicate for aflock action attestations.
type ActionPredicate struct {
	Action      string                 `json:"action"`
	SessionID   string                 `json:"sessionId"`
	ToolName    string                 `json:"toolName"`
	ToolUseID   string                 `json:"toolUseId"`
	ToolInput   map[string]interface{} `json:"toolInput,omitempty"`
	Decision    string                 `json:"decision"`
	Reason      string                 `json:"reason,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
	AgentID     string                 `json:"agentId,omitempty"`
	Metrics     *MetricsPredicate      `json:"metrics,omitempty"`
}

// MetricsPredicate contains metrics at the time of the action.
type MetricsPredicate struct {
	CumulativeTokensIn  int64   `json:"cumulativeTokensIn"`
	CumulativeTokensOut int64   `json:"cumulativeTokensOut"`
	CumulativeCostUSD   float64 `json:"cumulativeCostUSD"`
	TurnNumber          int     `json:"turnNumber"`
	ToolCallNumber      int     `json:"toolCallNumber"`
}

// Envelope is a DSSE envelope.
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}

// Signature is a DSSE signature.
type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// CreateActionAttestation creates an attestation for an action.
func (s *Signer) CreateActionAttestation(
	ctx context.Context,
	record aflock.ActionRecord,
	sessionID string,
	metrics *aflock.SessionMetrics,
) (*Envelope, error) {
	// Parse tool input
	var toolInput map[string]interface{}
	if record.ToolInput != nil {
		json.Unmarshal(record.ToolInput, &toolInput)
	}

	// Build predicate
	predicate := ActionPredicate{
		Action:    "tool_call",
		SessionID: sessionID,
		ToolName:  record.ToolName,
		ToolUseID: record.ToolUseID,
		ToolInput: toolInput,
		Decision:  record.Decision,
		Reason:    record.Reason,
		Timestamp: record.Timestamp,
	}

	if s.identity != nil {
		predicate.AgentID = s.identity.SPIFFEID.String()
	}

	if metrics != nil {
		predicate.Metrics = &MetricsPredicate{
			CumulativeTokensIn:  metrics.TokensIn,
			CumulativeTokensOut: metrics.TokensOut,
			CumulativeCostUSD:   metrics.CostUSD,
			TurnNumber:          metrics.Turns,
			ToolCallNumber:      metrics.ToolCalls,
		}
	}

	// Build statement
	statement := Statement{
		Type: StatementType,
		Subject: []Subject{
			{
				Name: fmt.Sprintf("session:%s/action:%s", sessionID, record.ToolUseID),
				Digest: map[string]string{
					"sha256": computeSHA256(record.ToolInput),
				},
			},
		},
		PredicateType: PredicateTypeAflockAction,
		Predicate:     predicate,
	}

	return s.Sign(ctx, statement)
}

// Sign signs a statement and returns a DSSE envelope.
func (s *Signer) Sign(ctx context.Context, statement Statement) (*Envelope, error) {
	// Serialize statement
	payload, err := json.Marshal(statement)
	if err != nil {
		return nil, fmt.Errorf("marshal statement: %w", err)
	}

	// Base64 encode payload
	payloadB64 := base64.StdEncoding.EncodeToString(payload)

	// Create PAE (Pre-Authentication Encoding)
	pae := createPAE(PayloadType, payload)

	// Sign PAE
	var sig []byte
	var keyID string

	if s.identity != nil {
		// Sign with SPIRE-provided key
		sig, err = signWithPrivateKey(s.identity.PrivateKey, pae)
		if err != nil {
			return nil, fmt.Errorf("sign with SPIRE key: %w", err)
		}
		keyID = s.identity.SPIFFEID.String()
	} else {
		return nil, fmt.Errorf("no signing identity available")
	}

	envelope := &Envelope{
		PayloadType: PayloadType,
		Payload:     payloadB64,
		Signatures: []Signature{
			{
				KeyID: keyID,
				Sig:   base64.StdEncoding.EncodeToString(sig),
			},
		},
	}

	return envelope, nil
}

// createPAE creates Pre-Authentication Encoding for DSSE.
func createPAE(payloadType string, payload []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s",
		len(payloadType), payloadType,
		len(payload), string(payload)))
}

// signWithPrivateKey signs data using the provided private key.
func signWithPrivateKey(privateKey interface{}, data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)

	switch key := privateKey.(type) {
	case *ecdsa.PrivateKey:
		return ecdsa.SignASN1(rand.Reader, key, hash[:])
	case crypto.Signer:
		return key.Sign(rand.Reader, hash[:], crypto.SHA256)
	default:
		return nil, fmt.Errorf("unsupported key type: %T", privateKey)
	}
}

// computeSHA256 computes SHA256 hash of data.
func computeSHA256(data []byte) string {
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash)
}

// ExportCertificatePEM exports the identity certificate as PEM.
func (s *Signer) ExportCertificatePEM() ([]byte, error) {
	if s.identity == nil || s.identity.Certificate == nil {
		return nil, fmt.Errorf("no identity certificate available")
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: s.identity.Certificate.Raw,
	}), nil
}

// ExportTrustBundlePEM exports the trust bundle as PEM.
func (s *Signer) ExportTrustBundlePEM() ([]byte, error) {
	if s.identity == nil || len(s.identity.TrustBundle) == 0 {
		return nil, fmt.Errorf("no trust bundle available")
	}

	var bundle []byte
	for _, cert := range s.identity.TrustBundle {
		bundle = append(bundle, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})...)
	}

	return bundle, nil
}

// VerifyEnvelope verifies a DSSE envelope signature.
func VerifyEnvelope(envelope *Envelope, trustedCerts []*x509.Certificate) error {
	if len(envelope.Signatures) == 0 {
		return fmt.Errorf("no signatures in envelope")
	}

	// Decode payload
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return fmt.Errorf("decode payload: %w", err)
	}

	// Create PAE
	pae := createPAE(envelope.PayloadType, payload)
	hash := sha256.Sum256(pae)

	// Verify each signature
	for _, sig := range envelope.Signatures {
		sigBytes, err := base64.StdEncoding.DecodeString(sig.Sig)
		if err != nil {
			return fmt.Errorf("decode signature: %w", err)
		}

		// Find matching certificate
		verified := false
		for _, cert := range trustedCerts {
			if ecdsaKey, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
				if ecdsa.VerifyASN1(ecdsaKey, hash[:], sigBytes) {
					verified = true
					break
				}
			}
		}

		if !verified {
			return fmt.Errorf("signature verification failed for keyid %s", sig.KeyID)
		}
	}

	return nil
}
