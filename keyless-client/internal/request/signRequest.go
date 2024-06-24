package request

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"keyless-client/internal/slogger"
	"log/slog"
	"net/http"
)

var signLogger = slogger.Logger

type SignRequest struct {
	Kid     string            `json:"kid"`
	Digest  string            `json:"digest"`
	Options crypto.SignerOpts `json:"options"`
}
type SignRequestMarshal struct {
	Scheme  tls.SignatureScheme `json:"scheme"`
	Digest  string              `json:"digest"`
	Options map[string]any      `json:"options"`
}
type SignResponse struct {
	Kid       string `json:"kid"`
	Signature string `json:"signature"`
	Error     string `json:"error"`
}
type SignProperties struct {
	Kid       string
	Signature []byte
}

func NewSignRequest(kid string, digest []byte, opts crypto.SignerOpts) *SignRequest {
	return &SignRequest{
		Kid:     kid,
		Digest:  base64.URLEncoding.EncodeToString(digest),
		Options: opts,
	}
}
func (req *SignRequest) Json() ([]byte, error) {
	return json.Marshal(req)
}

func (res *SignResponse) validate() error {
	if res.Error != "" {
		return errors.New(res.Error)
	}
	if res.Kid == "" {
		return errors.New("no kid found")
	}
	if res.Signature == "" {
		return errors.New("no signature found")
	}
	return nil
}

func (res *SignResponse) properties() (*SignProperties, error) {
	if err := res.validate(); err != nil {
		signLogger.Error("validation error", slogger.ErrorAttr(err))
		return nil, err
	}
	if signature, err := base64.URLEncoding.DecodeString(res.Signature); err != nil {
		signLogger.Error("base64 encoding error", slogger.ErrorAttr(err))
		return nil, err
	} else {
		return &SignProperties{
			Kid:       res.Kid,
			Signature: signature,
		}, nil
	}
}

func SendSignRequest(uri string, kid string, digest []byte, opts crypto.SignerOpts) (*SignProperties, error) {
	signLogger.Debug("sending signing request", slog.String("uri", uri), slog.String("kid", kid))
	buf := bytes.Buffer{}
	if raw, err := NewSignRequest(kid, digest, opts).Json(); err != nil {
		signLogger.Error("json encoding error", slogger.ErrorAttr(err))
		return nil, err
	} else {
		buf.Write(raw)
	}

	var req *http.Request
	if r, err := http.NewRequest(http.MethodPost, uri, &buf); err != nil {
		signLogger.Error("create request error", slogger.ErrorAttr(err))
		return nil, err
	} else {
		req = r
		req.Header.Set("Content-Type", "application/json")
	}

	var res *http.Response
	if r, err := http.DefaultClient.Do(req); err != nil {
		signLogger.Error("send request error", slogger.ErrorAttr(err))
		return nil, err
	} else {
		res = r
	}

	out := SignResponse{}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		signLogger.Error("json decoding error", slogger.ErrorAttr(err))
		return nil, err
	}
	return out.properties()
}
