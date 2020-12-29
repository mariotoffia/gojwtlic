package license

import "crypto/rsa"

// RSAKeypair holds public and private _RSA_ key pair
type RSAKeypair interface {
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
