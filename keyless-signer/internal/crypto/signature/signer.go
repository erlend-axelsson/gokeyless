package signature

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"net/http"
)

// CustomSigner is a crypto.Signer that uses the client certificate and key to sign

type CustomSigner struct {
	private crypto.PrivateKey
	public  crypto.PublicKey
}

func (k *CustomSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	switch k.private.(type) {
	case *rsa.PrivateKey:
		return k.private.(*rsa.PrivateKey).Sign(rand, digest, opts)
	case *ecdsa.PrivateKey:
		return k.private.(*ecdsa.PrivateKey).Sign(rand, digest, opts)
	case ed25519.PrivateKey:
		return k.private.(ed25519.PrivateKey).Sign(rand, digest, opts)
	}
	return nil, fmt.Errorf("unsupported private key type: %T", k.private)
}
func (k *CustomSigner) Public() crypto.PublicKey {
	return k.public
}

type RsaSigner struct {
	signFunc SignFunc
	public   *rsa.PrivateKey
}
type EcSigner struct {
	signFunc SignFunc
	public   *ecdsa.PrivateKey
}
type EdSigner struct {
	signFunc SignFunc
	public   ed25519.PrivateKey
}

type ClientSigner struct {
	scheme   tls.SignatureScheme
	vaultUri string
	kid      string
}
type signRequest struct {
	Scheme  tls.SignatureScheme `json:"scheme"`
	Digest  string              `json:"digest"`
	Options crypto.SignerOpts   `json:"options"`
}
type signResponse struct {
	Kid       string `json:"kid"`
	Signature string `json:"signature"`
	Error     string `json:"error"`
}
type pubKeyRequest struct {
	Scheme tls.SignatureScheme `json:"scheme"`
}
type pubKeyResponse struct {
	Kid       string `json:"kid"`
	PublicKey string `json:"publicKey"`
	Error     string `json:"error"`
}

func postJson[T any](uri string, kid string, payload []byte, out *T) error {
	buf := bytes.Buffer{}
	buf.Write(payload)
	req, err := http.NewRequest(http.MethodPost, uri, &buf)
	if err != nil {
		return err
	}
	if kid != "" {
		req.Header.Set("x-kid", kid)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	err = json.NewDecoder(res.Body).Decode(out)
	if err != nil {
		return err
	}
	return nil
}

func (c *ClientSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	bodyContent, err := json.Marshal(
		signRequest{
			Scheme:  c.scheme,
			Digest:  base64.URLEncoding.EncodeToString(digest),
			Options: opts,
		},
	)
	signRes := signResponse{}
	if err = postJson(c.vaultUri, c.kid, bodyContent, &signRes); err != nil {
		return nil, err
	} else if signRes.Error != "" {
		return nil, errors.New(signRes.Error)
	}
	c.kid = signRes.Kid

	return base64.URLEncoding.DecodeString(signRes.Signature)
}

func (c *ClientSigner) Public() crypto.PublicKey {
	bodyContent, err := json.Marshal(
		pubKeyRequest{
			Scheme: c.scheme,
		},
	)
	signRes := pubKeyResponse{}
	if err = postJson(c.vaultUri, c.kid, bodyContent, &signRes); err != nil {
		return nil
	} else if signRes.Error != "" {
		return nil
	}
	c.kid = signRes.Kid

	if raw, decodeErr := base64.URLEncoding.DecodeString(signRes.PublicKey); decodeErr != nil {
		return nil
	} else if pubKey, parseErr := ssh.ParsePublicKey(raw); parseErr != nil {
		return nil
	} else {
		return pubKey
	}
}
