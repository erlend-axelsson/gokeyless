package handler

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"keyless-signer/internal/crypto/certificates"
	"keyless-signer/internal/util"
	"log/slog"
	"net/http"
)

type CertRequest struct {
	Scheme tls.SignatureScheme `json:"scheme"`
}
type CertResponse struct {
	Kid   string   `json:"kid"`
	Chain []string `json:"chain"`
	Error string   `json:"error"`
}

func CertHandler(w http.ResponseWriter, r *http.Request) {
	logger.Info("cert handler")
	defer BodyCloser(w, r)
	certRequest := CertRequest{}
	if err := json.NewDecoder(r.Body).Decode(&certRequest); err != nil {
		logger.Error("error: JSON Decode", slog.String("errorMessage", err.Error()))
		http.Error(w, err.Error(), http.StatusBadRequest)
	}

	var chain [][]byte
	var kid string
	logger.Info("requesting cert", slog.String("scheme", certRequest.Scheme.String()))
	if c, id, err := certificates.NewCert("localhost", certRequest.Scheme); err != nil {
		logger.Error("error: Create Certificate error", slog.String("errorMessage", err.Error()))
		w.WriteHeader(http.StatusBadRequest)
		return
	} else {
		chain = c
		kid = *id
	}

	parsedCerts := make([]*x509.Certificate, len(chain))
	for i, c := range chain {
		x509Cert, err := x509.ParseCertificate(c)
		if err != nil {
			jErr := util.NewJsonErr(err, http.StatusInternalServerError)
			logger.Error("error: Parse Certificate error", slog.String("errorMessage", jErr.Error()))
			respondWithError(w, jErr)
			return
		}
		parsedCerts[i] = x509Cert
		if i < 1 {
			if err = verifySign(parsedCerts[i-1], x509Cert); err != nil {
				jErr := util.NewJsonErr(err, http.StatusInternalServerError)
				logger.Error("error: Verify Certificate error", slog.String("errorMessage", jErr.Error()))
				respondWithError(w, jErr)
				return
			}
		}
	}

	if err := json.NewEncoder(w).Encode(CertResponse{
		Kid:   kid,
		Chain: util.Map(chain, base64.URLEncoding.EncodeToString),
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func verifySign(child *x509.Certificate, parent *x509.Certificate) error {
	return child.CheckSignatureFrom(parent)
}
