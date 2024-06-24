package certificates

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"log"
	"math/big"
	"net"
	"strings"
	"time"
)

var rootCa = &pkix.Name{
	Country:      []string{"NO"},
	Organization: []string{"ERL-AXE CA"},
	Locality:     []string{"OSLO"},
	CommonName:   "Root CA",
}
var rootCA, caKey = func() (*x509.Certificate, crypto.PrivateKey) {
	cert, pk, err := generateCert(CertOpts{
		subject: rootCa,
		issuer:  rootCa,
		host:    "localhost",
		rsaBits: RSA2048,
		isCA:    true,
		parent:  nil,
	})
	if err != nil {
		// non-recoverable error
		log.Fatal(err)
	}
	return cert, pk
}()
var sigServer = &pkix.Name{
	Country:      []string{"NO"},
	Organization: []string{"ERL-AXE signer"},
	Locality:     []string{"OSLO"},
	CommonName:   "Intermediate CA",
}
var signerCert, signerKey = func() (*x509.Certificate, crypto.PrivateKey) {
	cert, pk, err := generateCert(CertOpts{
		issuer:    rootCa,
		subject:   sigServer,
		host:      "localhost",
		rsaBits:   RSA2048,
		isCA:      true,
		parent:    rootCA,
		parentKey: caKey,
	})
	if err != nil {
		// non-recoverable error
		log.Fatal(err)
	}
	return cert, pk
}()

var defaultSubject = &pkix.Name{
	CommonName: "localhost",
}

var CertStore = make(map[string]*tls.Certificate)

func publicKey(priv any) any {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public().(ed25519.PublicKey)
	default:
		return nil
	}

}

func nowPlusYear() time.Time {
	now := time.Now()
	return now.AddDate(1, 0, 0)
}

type CertOpts struct {
	subject    *pkix.Name
	issuer     *pkix.Name
	host       string
	ecdsaCurve CurveId
	ed25519Key bool
	rsaBits    RSABitLength
	validFrom  string
	notAfter   string
	isCA       bool
	parent     *x509.Certificate
	parentKey  crypto.PrivateKey
}

func certOpts() CertOpts {
	return CertOpts{
		subject:   defaultSubject,
		issuer:    sigServer,
		host:      "localhost",
		isCA:      false,
		parent:    signerCert,
		parentKey: signerKey,
	}
}

func getECDSAKey(curve string) (crypto.PrivateKey, error) {
	var privateKey any
	var err error
	switch curve {
	case CurveP256:
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case CurveP384:
		privateKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case CurveP521:
		privateKey, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		log.Fatalf("Unrecognized elliptic curve: %s", curve)
	}
	return privateKey, err
}

func getED25519Key() (crypto.PrivateKey, error) {
	var privateKey any
	var err error
	_, privateKey, err = ed25519.GenerateKey(rand.Reader)
	return privateKey, err
}

func getRSAKey(bitLen int) (crypto.PrivateKey, error) {
	var privateKey any
	var err error
	switch bitLen {
	case RSA1024:
		privateKey, err = rsa.GenerateKey(rand.Reader, bitLen)
	case RSA2048:
		privateKey, err = rsa.GenerateKey(rand.Reader, bitLen)
	case RSA4096:
		privateKey, err = rsa.GenerateKey(rand.Reader, bitLen)
	default:
		privateKey = nil
		err = fmt.Errorf("unsupported bit length: %d", bitLen)
	}
	return privateKey, err
}

type RSABitLength = int

const (
	RSA1024 RSABitLength = 1024
	RSA2048 RSABitLength = 2048
	RSA4096 RSABitLength = 4096
)

type CurveId = string

const (
	CurveP256 CurveId = "P256"
	CurveP384 CurveId = "P384"
	CurveP521 CurveId = "P521"
)

func NewCert(host string, scheme tls.SignatureScheme) ([][]byte, *string, error) {
	var keyID string
	if id, err := uuid.NewUUID(); err != nil {
		return nil, nil, err
	} else {
		keyID = id.String()
	}

	opts := certOpts()
	opts.host = host
	switch scheme {
	case tls.PKCS1WithSHA256:
		opts.rsaBits = RSA2048
	case tls.PKCS1WithSHA384:
		opts.rsaBits = RSA2048
	case tls.PKCS1WithSHA512:
		opts.rsaBits = RSA4096
	case tls.PSSWithSHA256:
		opts.rsaBits = RSA2048
	case tls.PSSWithSHA384:
		opts.rsaBits = RSA2048
	case tls.PSSWithSHA512:
		opts.rsaBits = RSA4096
	case tls.ECDSAWithP256AndSHA256:
		opts.ecdsaCurve = CurveP256
	case tls.ECDSAWithP384AndSHA384:
		opts.ecdsaCurve = CurveP384
	case tls.ECDSAWithP521AndSHA512:
		opts.ecdsaCurve = CurveP521
	case tls.Ed25519:
		opts.ed25519Key = true
	}

	if crt, key, err := generateCert(opts); err != nil {
		return nil, nil, err
	} else {
		chain := [][]byte{crt.Raw, signerCert.Raw, rootCA.Raw}
		CertStore[keyID] = &tls.Certificate{
			Certificate: chain,
			PrivateKey:  key,
			Leaf:        crt,
		}
		return chain, &keyID, nil
	}

}

func generateCert(opts CertOpts) (*x509.Certificate, crypto.PrivateKey, error) {
	if len(opts.host) == 0 {
		log.Fatalf("Missing required --host parameter")
	}
	var privateKey any
	var err error

	if len(opts.ecdsaCurve) != 0 {
		privateKey, err = getECDSAKey(opts.ecdsaCurve)
	} else if opts.ed25519Key {
		privateKey, err = getED25519Key()
	} else {
		privateKey, err = getRSAKey(opts.rsaBits)
	}
	if err != nil {
		return nil, nil, err
	}

	// ECDSA, ED25519 and RSA subject keys should have the DigitalSignature
	// KeyUsage bits set in the x509.Certificate template

	keyUsage := x509.KeyUsageDigitalSignature

	// Only RSA subject keys should have the KeyEncipherment KeyUsage bits set. In
	// the context of TLS this KeyUsage is particular to RSA key exchange and
	// authentication.

	if _, isRSA := privateKey.(*rsa.PrivateKey); isRSA {
		keyUsage |= x509.KeyUsageKeyEncipherment
	}

	var notBefore time.Time
	var notAfter time.Time

	if len(opts.validFrom) == 0 {
		notBefore = time.Now()
	} else {
		notBefore, err = time.Parse(time.RFC3339, opts.validFrom)
		if err != nil {
			return nil, nil, err
		}
	}
	if len(opts.notAfter) == 0 {
		notAfter = nowPlusYear()
	} else {
		notAfter, err = time.Parse(time.RFC3339, opts.notAfter)
		if err != nil {
			return nil, nil, err
		}
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}

	if opts.issuer == nil {
		return nil, nil, errors.New("no issuer specified")
	}
	if opts.subject == nil {
		return nil, nil, errors.New("no subject specified")
	}

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Issuer:                *opts.issuer,
		Subject:               *opts.subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	hosts := strings.Split(opts.host, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	var parent = &template
	var parentKey crypto.PrivateKey = privateKey
	if opts.isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}
	if opts.parent != nil {
		parent = opts.parent
		parentKey = opts.parentKey
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, parent, publicKey(privateKey), parentKey)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}
	return cert, privateKey, nil
}
