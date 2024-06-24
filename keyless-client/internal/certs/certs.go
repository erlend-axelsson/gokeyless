package certs

import (
	"crypto/tls"
	"errors"
	"keyless-client/internal/env"
	"keyless-client/internal/request"
	"keyless-client/internal/signer"
	"keyless-client/internal/slogger"
	"keyless-client/internal/util"
	"log/slog"
	"slices"
	"strings"
)

var logger = slogger.Logger

var certStore = make(map[tls.SignatureScheme]*tls.Certificate)
var supportedSchemes = []tls.SignatureScheme{
	tls.PKCS1WithSHA256,
	tls.PKCS1WithSHA384,
	tls.PKCS1WithSHA512,
	tls.ECDSAWithP256AndSHA256,
	tls.ECDSAWithP384AndSHA384,
	tls.ECDSAWithP521AndSHA512,
	tls.PSSWithSHA256,
	tls.PSSWithSHA384,
	tls.PSSWithSHA512,
	tls.Ed25519,
}
var supportedSchemesString = schemeSliceString(supportedSchemes)

func GetCert(scheme tls.SignatureScheme) (*tls.Certificate, bool) {
	cert, ok := certStore[scheme]
	return cert, ok
}
func StoreCert(scheme tls.SignatureScheme, cert *tls.Certificate) {
	certStore[scheme] = cert
}

func filterUnsupportedSchemes(clientSchemes []tls.SignatureScheme) []tls.SignatureScheme {
	var result []tls.SignatureScheme
	for _, scheme := range supportedSchemes {
		if slices.Contains(clientSchemes, scheme) {
			result = append(result, scheme)
		}
	}
	return result
}

func GetClientCertificate(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return GetCertificate(newServerHandShakeInfo(info))
}
func GetSeverCertificate(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return GetCertificate(newClientHandShakeInfo(info))
}
func GetCertificate(info HandShakeInfo) (*tls.Certificate, error) {
	var crt *tls.Certificate
	validSchemes := filterUnsupportedSchemes(info.SignatureSchemes)

	if len(validSchemes) == 0 {
		logger.Error("no supported schemes found",
			slog.String("expected", supportedSchemesString),
			slog.String("actual", schemeSliceString(info.SignatureSchemes)),
		)
		return nil, errors.New("no supported schemes found")
	}
	for _, scheme := range validSchemes {
		if c, found := GetCert(scheme); found {
			crt = c
			break
		}
	}
	if crt != nil {
		return crt, nil
	}
	if crtProps, err := request.SendCertRequest(env.SigUrl+"/cert", validSchemes[0]); err != nil {
		return nil, err
	} else {
		crt = &tls.Certificate{}
		crt.Leaf = crtProps.Leaf
		crt.Certificate = crtProps.Chain
		crt.PrivateKey = signer.NewClientSigner(
			crtProps.Kid,
			env.SigUrl+"/sign",
			crtProps.Leaf.PublicKey,
			validSchemes[0],
		)
	}
	StoreCert(validSchemes[0], crt)
	return crt, nil
}

type HandShakeInfo struct {
	SignatureSchemes []tls.SignatureScheme
}

func newServerHandShakeInfo(info *tls.CertificateRequestInfo) HandShakeInfo {
	return HandShakeInfo{
		SignatureSchemes: info.SignatureSchemes,
	}
}
func newClientHandShakeInfo(info *tls.ClientHelloInfo) HandShakeInfo {
	return HandShakeInfo{
		SignatureSchemes: info.SignatureSchemes,
	}
}

func schemeSliceString(schemes []tls.SignatureScheme) string {
	return strings.Join(util.Map(schemes, schemeString), ", ")
}
func schemeString(scheme tls.SignatureScheme) string {
	return scheme.String()
}
