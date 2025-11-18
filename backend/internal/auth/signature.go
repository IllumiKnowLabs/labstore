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

	"github.com/DataLabTechTV/labstore/backend/internal/security"
	"github.com/DataLabTechTV/labstore/backend/pkg/iam"
)

const UnsignedPayload = "UNSIGNED-PAYLOAD"

type SigV4Request struct {
	Method               string
	CanonicalURI         string
	CanonicalQueryString string
	CanonicalHeaders     map[string]string
	Authorization        *Sigv4Authorization
	Timestamp            string
	PayloadHash          string
}

type Sigv4Authorization struct {
	Credential    *SigV4Credential
	SignedHeaders []string
	Signature     string
}

type SigV4Credential struct {
	AccessKey string
	SecretKey string
	Scope     string
}

type SigV4Result struct {
	Credential  *SigV4Credential
	Signature   string
	Timestamp   string
	IsStreaming bool
}

func VerifySigV4(r *http.Request) (*SigV4Result, error) {
	req, err := parseRequest(r)
	if err != nil {
		return nil, fmt.Errorf("sigv4: %w", err)
	}

	res, err := req.validateSignature()
	if err != nil {
		return nil, fmt.Errorf("sigv4: %w", err)
	}

	return res, nil
}

func parseRequest(r *http.Request) (*SigV4Request, error) {
	authorization := r.Header.Get("Authorization")
	slog.Debug("Parsing SigV4 request", "Authorization", security.TruncParamHeader(authorization, "Signature"))

	auth, err := parseAuthorization(authorization)
	if err != nil {
		return nil, err
	}

	payloadHash, err := validatePayloadHash(r)
	if err != nil {
		return nil, err
	}

	timestamp := r.Header.Get("X-Amz-Date")
	slog.Debug("Received timestamp", "X-Amz-Date", timestamp)

	canonicalURI := buildCanonicalURI(r.URL.Path)
	slog.Debug("Built canonical URI", "uri", canonicalURI)

	canonicalQueryString := buildCanonicalQueryString(r.URL.RawQuery)
	slog.Debug("Built canonical query string", "queryString", canonicalQueryString)

	canonicalHeaders := buildCanonicalHeaders(r, auth)
	slog.Debug("Built canonical headers", "headers", canonicalHeaders)

	res := &SigV4Request{
		Method:               r.Method,
		CanonicalURI:         canonicalURI,
		CanonicalQueryString: canonicalQueryString,
		CanonicalHeaders:     canonicalHeaders,
		Authorization:        auth,
		Timestamp:            timestamp,
		PayloadHash:          payloadHash,
	}

	return res, nil
}

// Check for SigV4 prefix, and extract credential, signed headers and signature
func parseAuthorization(authorization string) (*Sigv4Authorization, error) {
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
		"Extracted authorization header parts",
		"Credential", credential,
		"SignedHeaders", strings.Join(signedHeaders, ";"),
		"Signature", security.Trunc(signature),
	)

	cred, err := parseCredential(credential)
	if err != nil {
		return nil, err
	}

	res := &Sigv4Authorization{
		Credential:    cred,
		SignedHeaders: signedHeaders,
		Signature:     signature,
	}

	return res, nil
}

// Extract access key and scope, and retrieve secret key from IAM
func parseCredential(credential string) (*SigV4Credential, error) {
	credentialParts := strings.Split(credential, "/")

	accessKey := credentialParts[0]
	slog.Debug("Extracted access key from credential", "accessKey", accessKey)

	secretKey, ok := iam.Users[accessKey]
	if !ok {
		return nil, errors.New("invalid access key")
	}

	scope := strings.Join(credentialParts[1:], "/")
	slog.Debug("Extracted scope from credential", "scope", scope)

	res := &SigV4Credential{
		AccessKey: accessKey,
		SecretKey: secretKey,
		Scope:     scope,
	}

	return res, nil
}

func validatePayloadHash(r *http.Request) (string, error) {
	payloadHash := r.Header.Get("X-Amz-Content-SHA256")
	slog.Debug("Received payload hash", "X-Amz-Content-SHA256", security.Trunc(payloadHash))

	if payloadHash == UnsignedPayload || payloadHash == StreamingPayload {
		return payloadHash, nil
	}

	// Recompute body hash
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return "", errors.New("could not read body")
	}

	slog.Debug("Read body", "length", len(body))

	// Restore body
	r.Body = io.NopCloser(bytes.NewBuffer(body))

	bytePayloadHash, err := hex.DecodeString((payloadHash))
	if err != nil {
		return "", errors.New("could not decode payload hash")
	}

	byteRecomputedPayloadHash := sha256.Sum256(body)
	recomputedPayloadHash := hex.EncodeToString(byteRecomputedPayloadHash[:])

	slog.Debug(
		"Comparing payload hashes",
		"received", security.Trunc(payloadHash),
		"recomputed", security.Trunc(recomputedPayloadHash),
	)

	if hmac.Equal(bytePayloadHash, byteRecomputedPayloadHash[:]) {
		return payloadHash, nil
	}

	slog.Error("Received and recomputed payload hashes differ")
	return "", errors.New("payload hashes do not match")
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

func buildCanonicalHeaders(r *http.Request, auth *Sigv4Authorization) map[string]string {
	headers := make(map[string]string)

	for _, signedHeader := range auth.SignedHeaders {
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

// Recompute and validate SigV4 signature
func (req *SigV4Request) validateSignature() (*SigV4Result, error) {
	stringToSign := req.buildStringToSign()
	slog.Debug("Built string to sign", "stringToSign", security.TruncLastLine(stringToSign))

	signature, err := computeSignature(req.Authorization.Credential, stringToSign)
	if err != nil {
		return nil, errors.New("could not compute signature")
	}

	byteSignature, err := hex.DecodeString(req.Authorization.Signature)
	if err != nil {
		return nil, errors.New("could not decode original signature")
	}

	byteRecomputedSignature, err := hex.DecodeString((signature))
	if err != nil {
		return nil, errors.New("could not decode recomputed signature")
	}

	slog.Debug(
		"Comparing signatures",
		"received", security.Trunc(req.Authorization.Signature),
		"recomputed", security.Trunc(signature),
	)

	if hmac.Equal(byteSignature, byteRecomputedSignature) {
		isStreaming := req.PayloadHash == StreamingPayload

		res := &SigV4Result{
			Credential:  req.Authorization.Credential,
			Signature:   req.Authorization.Signature,
			Timestamp:   req.Timestamp,
			IsStreaming: isStreaming,
		}

		return res, nil
	}

	slog.Error("Received and recomputed signatures differ")
	return nil, errors.New("signatures do not match")
}

func (req *SigV4Request) buildCanonicalRequest() string {
	var canonicalRequest strings.Builder

	canonicalRequest.WriteString(req.Method)
	canonicalRequest.WriteString("\n")

	canonicalRequest.WriteString(req.CanonicalURI)
	canonicalRequest.WriteString("\n")

	canonicalRequest.WriteString(req.CanonicalQueryString)
	canonicalRequest.WriteString("\n")

	for _, header := range req.Authorization.SignedHeaders {
		canonicalRequest.WriteString(header)
		canonicalRequest.WriteString(":")
		canonicalRequest.WriteString(req.CanonicalHeaders[header])
		canonicalRequest.WriteString("\n")
	}

	canonicalRequest.WriteString("\n")

	canonicalRequest.WriteString(strings.Join(req.Authorization.SignedHeaders, ";"))
	canonicalRequest.WriteString("\n")

	canonicalRequest.WriteString(req.PayloadHash)

	return canonicalRequest.String()
}

func (req *SigV4Request) buildStringToSign() string {
	canonicalRequest := req.buildCanonicalRequest()
	slog.Debug("Built canonical request", "canonicalRequest", security.TruncLastLine(canonicalRequest))

	var stringToSign strings.Builder

	stringToSign.WriteString("AWS4-HMAC-SHA256")
	stringToSign.WriteString("\n")

	stringToSign.WriteString(req.Timestamp)
	stringToSign.WriteString("\n")

	stringToSign.WriteString(req.Authorization.Credential.Scope)
	stringToSign.WriteString("\n")

	hash := sha256.Sum256([]byte(canonicalRequest))
	stringToSign.WriteString(hex.EncodeToString(hash[:]))

	return stringToSign.String()
}

func computeSignature(cred *SigV4Credential, stringToSign string) (string, error) {
	scopeParts := strings.Split(cred.Scope, "/")

	if len(scopeParts) != 4 {
		return "", errors.New("scope must contain 4 parts")
	}

	date := scopeParts[0]
	region := scopeParts[1]
	service := scopeParts[2]

	dateKey := hmacSHA256([]byte("AWS4"+cred.SecretKey), []byte(date))
	dateRegionKey := hmacSHA256(dateKey, []byte(region))
	dateRegionServiceKey := hmacSHA256(dateRegionKey, []byte(service))
	signingKey := hmacSHA256(dateRegionServiceKey, []byte("aws4_request"))
	signature := hmacSHA256(signingKey, []byte(stringToSign))
	signatureString := hex.EncodeToString(signature)

	return signatureString, nil
}

func hmacSHA256(key, value []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(value)
	return mac.Sum(nil)
}
