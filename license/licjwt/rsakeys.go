package licjwt

import (
	"crypto/rand"
	"crypto/rsa"
	"io/ioutil"
	"log"

	jwt "github.com/dgrijalva/jwt-go"
)

func fatal(err error) {
	if err != nil {
		log.Fatal(err)
		panic(err)
	}
}

// KeysImpl implements the license.RSAKeypair interface
// that may handle public and optionally a private key.
type KeysImpl struct {
	verifyKey *rsa.PublicKey
	signKey   *rsa.PrivateKey
}

// NewKeys creates a new private and it's corresponding public key.
//
// This is useful when wanting to create a new signing certificate to
// use when singinging new licenses. Store the private key in a secure
// location!
//
// Use bits: 2048 or 4096.
func NewKeys(bits int) *KeysImpl {

	signKey, err := rsa.GenerateKey(rand.Reader, bits)
	fatal(err)

	return &KeysImpl{
		signKey:   signKey,
		verifyKey: &signKey.PublicKey,
	}

}

// NewKeysFromBuffer is same as `NewKeysFromFile` _except_ that is uses a buffer
// to initialize the keys. Same constrains applies as with `NewKeysFromFile`.
func NewKeysFromBuffer(pubKey, privKey []byte) *KeysImpl {

	var signKey *rsa.PrivateKey
	var verifyKey *rsa.PublicKey

	var err error

	if len(privKey) > 0 {

		signKey, err = jwt.ParseRSAPrivateKeyFromPEM(privKey)
		fatal(err)

		verifyKey = &signKey.PublicKey
	}

	if len(pubKey) > 0 && verifyKey != nil {

		verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(pubKey)
		fatal(err)

	}

	if verifyKey == nil {
		panic("Must specify at least a public key!")
	}

	return &KeysImpl{
		signKey:   signKey,
		verifyKey: verifyKey,
	}

}

// NewKeysFromFile creates a new instance of a RSAKeypair compatible struct.
//
// Specify a public key path to a pem file. If the _privKeyPay_ is specified
// no _pubKeyPath_ is needed since it will extract the public key from the
// private one.
func NewKeysFromFile(pubKeyPath, privKeyPath string) *KeysImpl {

	var signBytes []byte
	var verifyBytes []byte

	var err error

	if privKeyPath != "" {

		signBytes, err = ioutil.ReadFile(privKeyPath)
		fatal(err)

	}

	if pubKeyPath != "" {

		verifyBytes, err = ioutil.ReadFile(pubKeyPath)
		fatal(err)

	}

	return NewKeysFromBuffer(verifyBytes, signBytes)

}

// PublicKey returns the public key portion
//
// This function is *REQUIRED* to return a valid public key.
func (k *KeysImpl) PublicKey() *rsa.PublicKey {
	return k.verifyKey
}

// PrivateKey returns the private key portion
//
// This function may return `nil` if no private key has been
// assigned, hence can only be used in Verification not Generation!
func (k *KeysImpl) PrivateKey() *rsa.PrivateKey {
	return k.signKey
}
