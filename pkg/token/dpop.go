package token

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"
)

var (
	// ErrInvalidDPoPProof indicates malformed DPoP proof JWT.
	ErrInvalidDPoPProof = errors.New("invalid dpop proof")
	// ErrUnsupportedAlgorithm indicates non-EdDSA algorithm.
	ErrUnsupportedAlgorithm = errors.New("unsupported algorithm: only EdDSA is permitted")
	// ErrInvalidJWK indicates malformed or non-Ed25519 JWK.
	ErrInvalidJWK = errors.New("invalid jwk: expected OKP with Ed25519 curve")
	// ErrDPoPProofExpired indicates proof timestamp is outside acceptable clock skew.
	ErrDPoPProofExpired = errors.New("dpop proof expired or timestamp outside acceptable skew window")
	// ErrMethodMismatch indicates the proof htm did not match the request method.
	ErrMethodMismatch = errors.New("dpop proof htm (method) mismatch")
	// ErrURIMismatch indicates the proof htu did not match the request URI.
	ErrURIMismatch = errors.New("dpop proof htu (uri) mismatch")
	// ErrATHMismatch indicates the proof ath did not match the hash of the presented access token.
	ErrATHMismatch = errors.New("dpop proof ath (access token hash) mismatch")
	// ErrDPoPProofReplayed indicates proof jti has already been observed within the validity window.
	ErrDPoPProofReplayed = errors.New("dpop proof replayed: jti already consumed")
)

// JWK represents an RFC 8037 Octet Key Pair (OKP) for Ed25519.
type JWK struct {
	Kty string `json:"kty"` // Must be "OKP"
	Crv string `json:"crv"` // Must be "Ed25519"
	X   string `json:"x"`   // base64url-encoded public key without padding
}

// Thumbprint computes the RFC 7638 JWK Thumbprint for the OKP key.
// Canonical JSON order: {"crv":"Ed25519","kty":"OKP","x":"..."}
func (k JWK) Thumbprint() string {
	canonicalJSON := fmt.Sprintf(`{"crv":"%s","kty":"%s","x":"%s"}`, k.Crv, k.Kty, k.X)
	digest := sha256.Sum256([]byte(canonicalJSON))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

// DPoPKey encapsulates an ephemeral Ed25519 keypair for DPoP proof generation.
type DPoPKey struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
}

// GenerateDPoPKey generates a new ephemeral Ed25519 DPoP keypair in memory.
func GenerateDPoPKey() (*DPoPKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral ed25519 key: %w", err)
	}
	return &DPoPKey{
		PrivateKey: priv,
		PublicKey:  pub,
	}, nil
}

// JWK returns the RFC 8037 JWK representation of the public key.
func (k *DPoPKey) JWK() JWK {
	return JWK{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   base64.RawURLEncoding.EncodeToString(k.PublicKey),
	}
}

// Thumbprint returns the RFC 7638 thumbprint of the public key.
func (k *DPoPKey) Thumbprint() string {
	return k.JWK().Thumbprint()
}

// Zeroize explicitly overwrites the private key memory to prevent heap inspection extraction.
func (k *DPoPKey) Zeroize() {
	if k.PrivateKey != nil {
		for i := range k.PrivateKey {
			k.PrivateKey[i] = 0
		}
		runtime.KeepAlive(k.PrivateKey)
		k.PrivateKey = nil
	}
}

// DPoPHeader defines the JWS header for RFC 9449 DPoP proofs.
type DPoPHeader struct {
	Typ string `json:"typ"` // Must be "dpop+jwt"
	Alg string `json:"alg"` // Must be "EdDSA"
	JWK JWK    `json:"jwk"` // Public key
}

// DPoPPayload defines the JWT claims for RFC 9449 DPoP proofs.
type DPoPPayload struct {
	JTI string `json:"jti"`           // Unique proof ID
	HTM string `json:"htm"`           // HTTP method (or action string)
	HTU string `json:"htu"`           // HTTP URI (or resource identifier)
	IAT int64  `json:"iat"`           // Issued at epoch seconds
	ATH string `json:"ath,omitempty"` // Access Token Hash
}

// ComputeATH computes the RFC 9449 access token hash: base64url(sha256(accessToken)).
func ComputeATH(accessToken string) string {
	if accessToken == "" {
		return ""
	}
	digest := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

// GenerateRandomJTI produces a secure random identifier for JTI claims.
func GenerateRandomJTI() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("crypto rand failed: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// CreateProof generates an RFC 9449 compliant DPoP proof JWT.
func (k *DPoPKey) CreateProof(htm, htu, accessToken string) (string, error) {
	if k.PrivateKey == nil {
		return "", errors.New("cannot create proof: private key has been zeroized")
	}

	jti, err := GenerateRandomJTI()
	if err != nil {
		return "", err
	}

	header := DPoPHeader{
		Typ: "dpop+jwt",
		Alg: "EdDSA",
		JWK: k.JWK(),
	}

	payload := DPoPPayload{
		JTI: jti,
		HTM: strings.ToUpper(htm),
		HTU: htu,
		IAT: time.Now().UTC().Unix(),
		ATH: ComputeATH(accessToken),
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed marshaling header: %w", err)
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed marshaling payload: %w", err)
	}

	headerEnc := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadEnc := base64.RawURLEncoding.EncodeToString(payloadJSON)

	signingInput := headerEnc + "." + payloadEnc
	sig := ed25519.Sign(k.PrivateKey, []byte(signingInput))
	sigEnc := base64.RawURLEncoding.EncodeToString(sig)

	return signingInput + "." + sigEnc, nil
}

// ValidateProof verifies an RFC 9449 DPoP proof JWT.
// It verifies:
// 1. JWT format (header.payload.signature)
// 2. typ == "dpop+jwt" and alg == "EdDSA"
// 3. JWK curve is Ed25519 and type is OKP
// 4. Ed25519 signature validity
// 5. iat timestamp within maxSkew window
// 6. htm and htu match expectation
// 7. ath matches hash of provided accessToken
// 8. jti has not been replayed (via ReplayCache)
func ValidateProof(
	proofJWT string,
	expectedMethod string,
	expectedURI string,
	accessToken string,
	maxSkew time.Duration,
	replayCache ReplayCache,
	now time.Time,
) (*DPoPPayload, *JWK, error) {
	parts := strings.Split(proofJWT, ".")
	if len(parts) != 3 {
		return nil, nil, fmt.Errorf("%w: expected 3 dot-separated segments", ErrInvalidDPoPProof)
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, fmt.Errorf("%w: invalid base64 header: %w", ErrInvalidDPoPProof, err)
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("%w: invalid base64 payload: %w", ErrInvalidDPoPProof, err)
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, nil, fmt.Errorf("%w: invalid base64 signature: %w", ErrInvalidDPoPProof, err)
	}

	var header DPoPHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, nil, fmt.Errorf("%w: malformed header json: %w", ErrInvalidDPoPProof, err)
	}

	if header.Typ != "dpop+jwt" {
		return nil, nil, fmt.Errorf("%w: got typ '%s', expected 'dpop+jwt'", ErrInvalidDPoPProof, header.Typ)
	}

	if header.Alg != "EdDSA" {
		return nil, nil, fmt.Errorf("%w: got alg '%s'", ErrUnsupportedAlgorithm, header.Alg)
	}

	if header.JWK.Kty != "OKP" || header.JWK.Crv != "Ed25519" {
		return nil, nil, fmt.Errorf("%w: got kty '%s' crv '%s'", ErrInvalidJWK, header.JWK.Kty, header.JWK.Crv)
	}

	pubKeyBytes, err := base64.RawURLEncoding.DecodeString(header.JWK.X)
	if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
		return nil, nil, fmt.Errorf("%w: invalid public key length %d", ErrInvalidJWK, len(pubKeyBytes))
	}

	// Verify cryptographic signature
	signingInput := parts[0] + "." + parts[1]
	if !ed25519.Verify(ed25519.PublicKey(pubKeyBytes), []byte(signingInput), sigBytes) {
		return nil, nil, fmt.Errorf("%w: signature verification failed", ErrInvalidDPoPProof)
	}

	var payload DPoPPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, nil, fmt.Errorf("%w: malformed payload json: %w", ErrInvalidDPoPProof, err)
	}

	// Verify timestamp and skew
	proofTime := time.Unix(payload.IAT, 0).UTC()
	diff := now.Sub(proofTime)
	if diff < 0 {
		diff = -diff
	}
	if diff > maxSkew {
		return nil, nil, fmt.Errorf("%w: proof time %s differs from now %s by %v (max allowed: %v)",
			ErrDPoPProofExpired, proofTime, now.UTC(), diff, maxSkew)
	}

	// Verify HTM (method)
	if expectedMethod != "" && !strings.EqualFold(payload.HTM, expectedMethod) {
		return nil, nil, fmt.Errorf("%w: got '%s', expected '%s'", ErrMethodMismatch, payload.HTM, expectedMethod)
	}

	// Verify HTU (URI)
	if expectedURI != "" && payload.HTU != expectedURI {
		return nil, nil, fmt.Errorf("%w: got '%s', expected '%s'", ErrURIMismatch, payload.HTU, expectedURI)
	}

	// Verify ATH if access token is present
	if accessToken != "" {
		expectedATH := ComputeATH(accessToken)
		if subtle.ConstantTimeCompare([]byte(payload.ATH), []byte(expectedATH)) != 1 {
			return nil, nil, fmt.Errorf("%w: got '%s', expected '%s'", ErrATHMismatch, payload.ATH, expectedATH)
		}
	}

	// Replay check
	if replayCache != nil {
		expTime := proofTime.Add(maxSkew)
		if err := replayCache.CheckAndSet(payload.JTI, expTime); err != nil {
			return nil, nil, fmt.Errorf("%w: %w", ErrDPoPProofReplayed, err)
		}
	}

	return &payload, &header.JWK, nil
}
