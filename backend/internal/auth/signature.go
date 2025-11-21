package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/IllumiKnowLabs/labstore/backend/internal/security"
	"github.com/IllumiKnowLabs/labstore/backend/pkg/iam"
)

type sigV4Request struct {
	method               string
	canonicalURI         string
	canonicalQueryString string
	canonicalHeaders     map[string]string
	authorization        *sigV4Authorization
	timestamp            string
	payloadHash          string
}

type sigV4Authorization struct {
	credential    *sigV4Credential
	signedHeaders []string
	signature     string
}

type sigV4Credential struct {
	AccessKey string
	secretKey string
	scope     string
}

type sigV4Result struct {
	Credential  *sigV4Credential
	Signature   string
	Timestamp   string
	IsStreaming bool
}

func VerifySigV4(r *http.Request) (*sigV4Result, error) {
	req, err := newSigV4Request(r)
	if err != nil {
		return nil, fmt.Errorf("sigv4: %w", err)
	}

	if err := req.validatePayloadHash(r); err != nil {
		return nil, fmt.Errorf("sigv4: %w", err)
	}

	res, err := req.validateSignature()
	if err != nil {
		return nil, fmt.Errorf("sigv4: %w", err)
	}

	return res, nil
}

func newSigV4Request(r *http.Request) (*sigV4Request, error) {
	authorization := r.Header.Get("Authorization")
	slog.Debug("parsing sigv4 request", "authorization", security.TruncParamHeader(authorization, "Signature"))

	auth, err := newSigV4Authorization(authorization)
	if err != nil {
		return nil, err
	}

	payloadHash := r.Header.Get("X-Amz-Content-SHA256")
	slog.Debug("payload hash", "x-amz-content-sha256", security.Trunc(payloadHash))

	timestamp := r.Header.Get("X-Amz-Date")
	slog.Debug("timestamp", "x-amz-date", timestamp)

	canonicalURI := buildCanonicalURI(r.URL.Path)
	slog.Debug("canonical uri", "uri", canonicalURI)

	canonicalQueryString := buildCanonicalQueryString(r.URL.RawQuery)
	slog.Debug("canonical query string", "query_string", canonicalQueryString)

	canonicalHeaders := buildCanonicalHeaders(r, auth)
	slog.Debug("canonical headers", "headers", canonicalHeaders)

	res := &sigV4Request{
		method:               r.Method,
		canonicalURI:         canonicalURI,
		canonicalQueryString: canonicalQueryString,
		canonicalHeaders:     canonicalHeaders,
		authorization:        auth,
		timestamp:            timestamp,
		payloadHash:          payloadHash,
	}

	return res, nil
}

// Check for SigV4 prefix, and extract credential, signed headers and signature
func newSigV4Authorization(authorization string) (*sigV4Authorization, error) {
	auth, ok := strings.CutPrefix(authorization, "AWS4-HMAC-SHA256 ")
	if !ok {
		return nil, errors.New("header Authorization must start with AWS4-HMAC-SHA256")
	}

	parts := strings.Split(auth, ",")

	var credential string
	var signedHeaders []string
	var signature string

	for _, p := range parts {
		p = strings.TrimSpace(p)

		if after, ok := strings.CutPrefix(p, "Credential="); ok {
			credential = after
		}

		if after, ok := strings.CutPrefix(p, "SignedHeaders="); ok {
			signedHeaders = strings.Split(after, ";")
		}

		if after, ok := strings.CutPrefix(p, "Signature="); ok {
			signature = after
		}
	}

	if credential == "" {
		return nil, errors.New("header Credential is empty")
	}

	if len(signedHeaders) == 0 {
		return nil, errors.New("header SignedHeaders is empty")
	}

	if signature == "" {
		return nil, errors.New("header Signature is empty")
	}

	slog.Debug(
		"authorization",
		"credential", credential,
		"signed_headers", strings.Join(signedHeaders, ";"),
		"signature", security.Trunc(signature),
	)

	cred, err := newSigV4Credential(credential)
	if err != nil {
		return nil, err
	}

	res := &sigV4Authorization{
		credential:    cred,
		signedHeaders: signedHeaders,
		signature:     signature,
	}

	return res, nil
}

// Extract access key and scope, and retrieve secret key from IAM
func newSigV4Credential(credential string) (*sigV4Credential, error) {
	credentialParts := strings.Split(credential, "/")

	accessKey := credentialParts[0]

	secretKey, ok := iam.Users[accessKey]
	if !ok {
		return nil, errors.New("invalid access key")
	}

	scope := strings.Join(credentialParts[1:], "/")

	slog.Debug("credential", "access_key", accessKey, "scope", scope)

	res := &sigV4Credential{
		AccessKey: accessKey,
		secretKey: secretKey,
		scope:     scope,
	}

	return res, nil
}

func buildCanonicalURI(path string) string {
	parts := strings.Split(path, "/")

	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}

	canonicalURI := strings.Join(parts, "/")

	return canonicalURI
}

func buildCanonicalQueryString(rawQuery string) string {
	m, _ := url.ParseQuery(rawQuery)

	keys := make([]string, 0, len(m))

	for k := range m {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	var parts []string

	for _, key := range keys {
		values := m[key]
		sort.Strings(values)

		for _, value := range values {
			parts = append(parts, queryEncode(key)+"="+queryEncode(value))
		}
	}

	return strings.Join(parts, "&")
}

func queryEncode(kv string) string {
	esc := url.QueryEscape(kv)
	esc = strings.ReplaceAll(esc, "+", "%20")
	esc = strings.ReplaceAll(esc, "%7E", "~")
	return esc
}

func buildCanonicalHeaders(r *http.Request, auth *sigV4Authorization) map[string]string {
	headers := make(map[string]string)

	for _, signedHeader := range auth.signedHeaders {
		header := strings.ToLower(signedHeader)

		var value string

		if header == "host" {
			value = r.Host
		} else {
			value = r.Header.Get(signedHeader)
		}

		headers[header] = strings.TrimSpace(value)
	}

	return headers
}

func (req *sigV4Request) validatePayloadHash(r *http.Request) error {
	if req.payloadHash == unsignedPayload || req.payloadHash == streamingPayload {
		return nil
	}

	// Recompute body hash
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return errors.New("could not read body")
	}

	slog.Debug("body", "length", len(body))

	// Restore body
	r.Body = io.NopCloser(bytes.NewBuffer(body))

	bytePayloadHash, err := hex.DecodeString((req.payloadHash))
	if err != nil {
		return errors.New("could not decode payload hash")
	}

	byteRecomputedPayloadHash := sha256.Sum256(body)
	recomputedPayloadHash := hex.EncodeToString(byteRecomputedPayloadHash[:])

	slog.Debug(
		"comparing payload hashes",
		"received", security.Trunc(req.payloadHash),
		"recomputed", security.Trunc(recomputedPayloadHash),
	)

	if hmac.Equal(bytePayloadHash, byteRecomputedPayloadHash[:]) {
		return nil
	}

	slog.Error("payload hashes differ")
	return errors.New("payload hashes do not match")
}

// Recompute and validate SigV4 signature
func (req *sigV4Request) validateSignature() (*sigV4Result, error) {
	stringToSign := req.buildStringToSign()
	slog.Debug("string to sign", "string_to_sign", security.TruncLastLine(stringToSign))

	signature, err := computeSignature(req.authorization.credential, stringToSign)
	if err != nil {
		return nil, errors.New("could not compute signature")
	}

	byteSignature, err := hex.DecodeString(req.authorization.signature)
	if err != nil {
		return nil, errors.New("could not decode original signature")
	}

	byteRecomputedSignature, err := hex.DecodeString((signature))
	if err != nil {
		return nil, errors.New("could not decode recomputed signature")
	}

	slog.Debug(
		"comparing signatures",
		"received", security.Trunc(req.authorization.signature),
		"recomputed", security.Trunc(signature),
	)

	if hmac.Equal(byteSignature, byteRecomputedSignature) {
		isStreaming := req.payloadHash == streamingPayload

		res := &sigV4Result{
			Credential:  req.authorization.credential,
			Signature:   req.authorization.signature,
			Timestamp:   req.timestamp,
			IsStreaming: isStreaming,
		}

		return res, nil
	}

	slog.Error("signatures differ")
	return nil, errors.New("signatures do not match")
}

func (req *sigV4Request) buildCanonicalRequest() string {
	var canonicalRequest strings.Builder

	canonicalRequest.WriteString(req.method)
	canonicalRequest.WriteString("\n")

	canonicalRequest.WriteString(req.canonicalURI)
	canonicalRequest.WriteString("\n")

	canonicalRequest.WriteString(req.canonicalQueryString)
	canonicalRequest.WriteString("\n")

	for _, header := range req.authorization.signedHeaders {
		canonicalRequest.WriteString(header)
		canonicalRequest.WriteString(":")
		canonicalRequest.WriteString(req.canonicalHeaders[header])
		canonicalRequest.WriteString("\n")
	}

	canonicalRequest.WriteString("\n")

	canonicalRequest.WriteString(strings.Join(req.authorization.signedHeaders, ";"))
	canonicalRequest.WriteString("\n")

	canonicalRequest.WriteString(req.payloadHash)

	return canonicalRequest.String()
}

func (req *sigV4Request) buildStringToSign() string {
	canonicalRequest := req.buildCanonicalRequest()
	slog.Debug("canonical request", "canonical_request", security.TruncLastLine(canonicalRequest))

	var stringToSign strings.Builder

	stringToSign.WriteString("AWS4-HMAC-SHA256")
	stringToSign.WriteString("\n")

	stringToSign.WriteString(req.timestamp)
	stringToSign.WriteString("\n")

	stringToSign.WriteString(req.authorization.credential.scope)
	stringToSign.WriteString("\n")

	hash := sha256.Sum256([]byte(canonicalRequest))
	stringToSign.WriteString(hex.EncodeToString(hash[:]))

	return stringToSign.String()
}
