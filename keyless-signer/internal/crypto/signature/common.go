package signature

type SignFunc func(digest []byte) (signature []byte, signatureErr error)
type Signer interface {
	Sign(payload []byte) (digest []byte, signature []byte, err error)
}
