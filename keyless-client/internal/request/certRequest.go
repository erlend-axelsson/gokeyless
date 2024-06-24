package request

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"keyless-client/internal/slogger"
	"log/slog"
	"net/http"
)

var certLogger = slogger.Logger

type CertRequest struct {
	Scheme tls.SignatureScheme `json:"scheme"`
}

type certResponse struct {
	Kid   string   `json:"kid"`
	Chain []string `json:"chain"`
	Error string   `json:"error"`
}

type CertProperties struct {
	Kid    string
	Chain  [][]byte
	Public crypto.PublicKey
	Leaf   *x509.Certificate
}

func (req *CertRequest) Json() ([]byte, error) {
	return json.Marshal(&req)
}

func (res *certResponse) validate() error {
	if res.Error != "" {
		return errors.New(res.Error)
	}
	if res.Kid == "" {
		return errors.New("no kid found")
	}
	if res.Chain == nil || len(res.Chain) == 0 {
		return errors.New("no certificate chain found")
	}
	return nil
}

func (res *certResponse) properties() (*CertProperties, error) {
	if err := res.validate(); err != nil {
		certLogger.Error("validation error", slogger.ErrorAttr(err))
		return nil, err
	}
	var chain = make([][]byte, len(res.Chain))
	for i, b64Cert := range res.Chain {
		if raw, err := base64.URLEncoding.DecodeString(b64Cert); err != nil {
			certLogger.Error("base64 decode error", slogger.ErrorAttr(err))
			return nil, err
		} else {
			chain[i] = raw
		}
	}
	if leaf, err := x509.ParseCertificate(chain[0]); err != nil {
		certLogger.Error("x509 parse error", slogger.ErrorAttr(err))
		return nil, err
	} else {
		return &CertProperties{
			Kid:    res.Kid,
			Chain:  chain,
			Public: leaf.PublicKey,
			Leaf:   leaf,
		}, nil
	}
}
func newCertRequest(scheme tls.SignatureScheme) *CertRequest {
	return &CertRequest{scheme}
}

func SendCertRequest(uri string, scheme tls.SignatureScheme) (*CertProperties, error) {
	certLogger.Debug("sending signing request", slog.String("uri", uri), slog.String("scheme", scheme.String()))
	buf := bytes.Buffer{}
	if raw, err := newCertRequest(scheme).Json(); err != nil {
		certLogger.Error("json encoding error", slogger.ErrorAttr(err))
		return nil, err
	} else {
		buf.Write(raw)
	}

	var req *http.Request
	if r, err := http.NewRequest(http.MethodPost, uri, &buf); err != nil {
		certLogger.Error("create request error", slogger.ErrorAttr(err))
		return nil, err
	} else {
		req = r
		req.Header.Set("Content-Type", "application/json")
	}

	var res *http.Response
	if r, err := http.DefaultClient.Do(req); err != nil {
		certLogger.Error("send request error", slogger.ErrorAttr(err))
		return nil, err
	} else {
		res = r
	}

	crtRes := certResponse{}
	if err := json.NewDecoder(res.Body).Decode(&crtRes); err != nil {
		certLogger.Error("json decode error", slogger.ErrorAttr(err))
		return nil, err
	}
	return crtRes.properties()
}
