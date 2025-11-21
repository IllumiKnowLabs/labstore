package auth

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/IllumiKnowLabs/labstore/backend/internal/security"
)

type sigV4ChunkedReader struct {
	body       io.ReadCloser
	prevSig    string
	credential *sigV4Credential
	timestamp  string

	reader *bufio.Reader
	header *sigV4ChunkHeader
	data   []byte
}

type sigV4ChunkHeader struct {
	size      int
	signature string
}

func NewSigV4ChunkedReader(r *http.Request, res *sigV4Result) *sigV4ChunkedReader {
	return &sigV4ChunkedReader{
		body:       r.Body,
		prevSig:    res.Signature,
		credential: res.Credential,
		timestamp:  res.Timestamp,
	}
}

func (r *sigV4ChunkedReader) Read(buf []byte) (int, error) {
	if r.reader == nil {
		r.reader = bufio.NewReader(r.body)
	}

	if len(r.data) > 0 {
		n := copy(buf, r.data)
		r.data = r.data[n:]
		return n, nil
	}

	if err := r.readChunkHeader(); err != nil {
		return 0, err
	}

	if r.header.size == 0 {
		return 0, io.EOF
	}

	if err := r.readChunkData(); err != nil {
		return 0, err
	}

	if err := r.readTrailingCRLF(); err != nil {
		return 0, err
	}

	if err := r.verifyChunkSigV4(); err != nil {
		return 0, err
	}

	r.prevSig = r.header.signature

	n := copy(buf, r.data)
	r.data = r.data[n:]

	return n, nil
}

func (r *sigV4ChunkedReader) Close() error {
	return r.body.Close()
}

func (r *sigV4ChunkedReader) readChunkHeader() error {
	line, err := r.reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return err
	}

	line = strings.TrimSuffix(line, "\r\n")

	headerParts := strings.SplitN(line, ";", 2)
	sizeHex, chunkSig := headerParts[0], headerParts[1]

	size, err := strconv.ParseInt(sizeHex, 16, 64)
	if err != nil {
		return err
	}

	sig, ok := strings.CutPrefix(chunkSig, "chunk-signature=")
	if !ok {
		return errors.New("could not find 'chunk-signature=' prefix")
	}

	r.header = &sigV4ChunkHeader{
		size:      int(size),
		signature: sig,
	}

	slog.Debug("chunk header", "size", r.header.size, "signature", security.Trunc(r.header.signature))

	return nil
}

func (r *sigV4ChunkedReader) readChunkData() error {
	r.data = make([]byte, r.header.size)

	if _, err := io.ReadFull(r.reader, r.data); err != nil {
		return err
	}

	slog.Debug("chunk data", "length", len(r.data))

	return nil
}

func (r *sigV4ChunkedReader) readTrailingCRLF() error {
	crlf := make([]byte, 2)

	if _, err := io.ReadFull(r.reader, crlf); err != nil || !bytes.Equal(crlf, []byte{'\r', '\n'}) {
		return errors.New("invalid chunk termination")
	}

	slog.Debug("chunk crlf")

	return nil
}

func (r *sigV4ChunkedReader) verifyChunkSigV4() error {
	stringToSign := r.buildChunkStringToSign()
	slog.Debug("string to sign", "string_to_sign", security.TruncLastLines(stringToSign, 3))

	recomputedSignature, err := computeSignature(r.credential, stringToSign)

	if err != nil {
		return err
	}

	byteSignature, err := hex.DecodeString(r.header.signature)
	if err != nil {
		return errors.New("could not decode original signature")
	}

	byteRecomputedSignature, err := hex.DecodeString((recomputedSignature))
	if err != nil {
		return errors.New("could not decode recomputed signature")
	}

	slog.Debug(
		"comparing chunk signatures",
		"original", security.Trunc(r.header.signature),
		"recomputed", security.Trunc(recomputedSignature),
	)

	if hmac.Equal(byteSignature, byteRecomputedSignature) {
		return nil
	}

	return errors.New("chunk signatures differ")
}

func (r *sigV4ChunkedReader) buildChunkStringToSign() string {
	var stringToSign strings.Builder

	stringToSign.WriteString("AWS4-HMAC-SHA256-PAYLOAD")
	stringToSign.WriteString("\n")

	stringToSign.WriteString(r.timestamp)
	stringToSign.WriteString("\n")

	stringToSign.WriteString(r.credential.scope)
	stringToSign.WriteString("\n")

	stringToSign.WriteString(r.prevSig)
	stringToSign.WriteString("\n")

	emptyHash := sha256.Sum256([]byte(""))
	stringToSign.WriteString(hex.EncodeToString(emptyHash[:]))
	stringToSign.WriteString("\n")

	chunkHash := sha256.Sum256(r.data)
	stringToSign.WriteString(hex.EncodeToString(chunkHash[:]))

	return stringToSign.String()
}
