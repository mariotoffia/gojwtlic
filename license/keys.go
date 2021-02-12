package license

import "crypto/rsa"

// KeyType represents a key type e.g. RSA or ECS
type KeyType string

const (
	// RSAKeyType is a _"RSA"_ key type.
	RSAKeyType KeyType = "RSA"
	// ECCNist is the NIST variants of the elliptic curve cryptography
	ECCNist KeyType = "ECC_NIST"
	// ECCSEGCG is a SEGCG elliptic curve cryptography key.
	ECCSEGCG KeyType = "ECC_SECG"
)

// KeyPair represents a pair of asymmetric keys. It may only include one key. If a key is
// omitted it's ID is an empty string.
type KeyPair interface {
	// PublicKeyID is the identity of the public key. It may be a filepath or an _AWS ARN_.
	PublicKeyID() string
	// PrivateKeyID is the identity of the private key. It may be a filepath or an _AWS ARN_.
	PrivateKeyID() string
	// Type returns the type of keypair is. For example _RSAKeyType_.
	Type() KeyType
	// KeyLength is the length of the key in bits, e.g. 382
	KeyLength() int
}

// KMSKeyPair represents the ability to get the public key from _AWS KMS_ using _ARN_ or alias to
// the private key to be used in signing of a _JWT_. The public key may be offloaded to local filesystem
// hence this keypair is searching the local filesystem for the public key first before trying to download
// it from the _KMS_.
//
// The private key is *never* exposed, since it is fully managed by _AWS KMS_ and therefore can be policy administered
// and security & compliance audited using e.g. CloudTrail, AWS Config, and Security Hub.
//
// The `PrivateKeyID()` is _REQUIRED_ to be a valid identifier to _uniquely_ qualify the _KMS_ private key (e.g. a _ARN_).
type KMSKeyPair interface {
	// KeyPair is it's base interface
	KeyPair
	// PublicKey returns the public key portion.
	//
	// Since _KMS_ is able to use different types of Keys e.g. RSA, ECS, this needs to be determined by
	// the `Type()` property. If e.g. _RSA_ this function will return a `*rsa.PublicKey`.
	//
	// This function will first check the cache if it exists there, it will use that first to avoid network communication.
	// If not found, it will try to download it from the _AWS KMS_ if the current process has sufficient rights to do such
	// operation.
	PublicKey(force bool) interface{}
}

// RSAKeyPair holds public and private _RSA_ key pair
type RSAKeyPair interface {
	// KeyPair is it's base interface
	KeyPair
	// PublicKey returns the public key portion
	//
	// This function is *REQUIRED* to return a valid public key.
	PublicKey() *rsa.PublicKey
	// PrivateKey returns the private key portion
	//
	// This function may return `nil` if no private key has been
	// assigned, hence can only be used in Verification not Generation!
	PrivateKey() *rsa.PrivateKey
}
