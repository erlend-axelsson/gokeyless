package signer

import (
	"crypto"
	"crypto/tls"
	"io"
	"keyless-client/internal/request"
	"keyless-client/internal/slogger"
)

var logger = slogger.Logger

type ClientSigner struct {
	scheme   tls.SignatureScheme
	vaultUri string
	kid      string
	pubKey   crypto.PublicKey
}

func NewClientSigner(kid, vaultUri string, pubKey crypto.PublicKey, scheme tls.SignatureScheme) crypto.Signer {
	return &ClientSigner{
		scheme:   scheme,
		vaultUri: vaultUri,
		kid:      kid,
		pubKey:   pubKey,
	}
}

func (c *ClientSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	logger.Debug("signing digest")
	if res, signErr := request.SendSignRequest(c.vaultUri, c.kid, digest, opts); signErr != nil {
		logger.Error("signing failed", slogger.ErrorAttr(err))
		return nil, signErr
	} else {
		return res.Signature, nil
	}
}

func (c *ClientSigner) Public() crypto.PublicKey {
	return c.pubKey
}
