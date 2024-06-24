package handler

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"keyless-signer/internal/crypto/certificates"
	"keyless-signer/internal/util"
	"log/slog"
	"net/http"
)

type SignRequest struct {
	Kid     string          `json:"kid"`
	Digest  string          `json:"digest"`
	Options json.RawMessage `json:"options"`
}

type SignResponse struct {
	Kid       string `json:"kid"`
	Signature string `json:"signature"`
	Error     string `json:"error"`
}

func SignHandler(w http.ResponseWriter, r *http.Request) {
	logger.Debug("sign handler")
	setContentJson(w)
	defer BodyCloser(w, r)
	var sReq SignRequest
	if req, err := DeserializeSignRequest(r.Body); err != nil {
		jErr := util.NewJsonErr(err, http.StatusBadRequest)
		logger.Error("error: DeserializeSignRequest", slog.String("errorMessage", jErr.Error()))
		respondWithError(w, jErr)
		return
	} else {
		sReq = req
	}

	var digest []byte
	if b, err := base64.URLEncoding.DecodeString(sReq.Digest); err != nil {
		jErr := util.NewJsonErr(err, http.StatusBadRequest)
		logger.Error(
			"error: DecodeString digest",
			slog.String("errorMessage", jErr.Error()),
			slog.String("value", sReq.Digest),
		)
		respondWithError(w, jErr)
		return
	} else {
		digest = b
	}

	var signerOpts crypto.SignerOpts
	if sigOpts, err := getSignerOpts(sReq.Options); err != nil {
		jErr := util.NewJsonErr(err, http.StatusBadRequest)
		logger.Error("error: getSignerOpts", slog.String("errorMessage", jErr.Error()))
		respondWithError(w, jErr)
		return
	} else {
		signerOpts = sigOpts
	}

	var pk crypto.PrivateKey
	if cert, found := certificates.CertStore[sReq.Kid]; !found || cert == nil {
		jErr := util.NewJsonErr(fmt.Errorf("certificate %s not found", sReq.Kid), http.StatusBadRequest)
		logger.Error("error: CertStore", slog.String("errorMessage", jErr.Error()))
		respondWithError(w, jErr)
		return
	} else {
		pk = cert.PrivateKey
	}

	var signer crypto.Signer
	if s, ok := pk.(crypto.Signer); !ok {
		jErr := util.NewJsonErr(fmt.Errorf("invalid signer: %+v", s), http.StatusInternalServerError)
		logger.Error("error: crypto.Signer", slog.String("errorMessage", jErr.Error()))
		respondWithError(w, jErr)
		return
	} else {
		signer = s
	}

	var signatureBytes []byte
	if sig, err := signer.Sign(rand.Reader, digest, signerOpts); err != nil {
		jErr := util.NewJsonErr(err, http.StatusInternalServerError)
		logger.Error("error: Sign", slog.String("errorMessage", jErr.Error()))
		respondWithError(w, jErr)
		return
	} else {
		signatureBytes = sig
	}

	if err := json.NewEncoder(w).Encode(&SignResponse{
		Kid:       sReq.Kid,
		Signature: base64.URLEncoding.EncodeToString(signatureBytes),
	}); err != nil {
		jErr := util.NewJsonErr(err, http.StatusInternalServerError)
		logger.Error("error: Encode", slog.String("errorMessage", jErr.Error()))
		respondWithError(w, jErr)
		return
	}
}

func getSignerOpts(opts json.RawMessage) (crypto.SignerOpts, error) {
	var hashNum crypto.Hash
	if err := strictJson(opts, &hashNum); err == nil {
		return hashNum, nil
	}
	pssOpts := rsa.PSSOptions{}
	if err := strictJson(opts, &pssOpts); err == nil {
		return &pssOpts, nil
	}
	edOpts := ed25519.Options{}
	if err := strictJson(opts, &edOpts); err == nil {
		return &edOpts, nil
	}
	return nil, fmt.Errorf("no options provided")
}

func DeserializeSignRequest(reader io.Reader) (SignRequest, error) {
	sReq := SignRequest{}
	if err := json.NewDecoder(reader).Decode(&sReq); err != nil {
		return sReq, err
	}
	return sReq, nil
}

func strictJson[T any](jsonBytes []byte, out T) error {
	decoder := json.NewDecoder(bytes.NewBuffer(jsonBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	return nil
}
