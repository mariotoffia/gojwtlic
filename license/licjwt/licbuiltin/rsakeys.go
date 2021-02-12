package licbuiltin

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"log"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/mariotoffia/gojwtlic/license"
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
	bits      int
	pubKeyID  string
	privKeyID string
}

// NewRSAKeys creates a new private and it's corresponding public key.
//
// This is useful when wanting to create a new signing certificate to
// use when singinging new licenses. Store the private key in a secure
// location!
//
// Use bits: 2048 or 4096.
func NewRSAKeys(bits int) *KeysImpl {

	signKey, err := rsa.GenerateKey(rand.Reader, bits)
	fatal(err)

	return &KeysImpl{
		signKey:   signKey,
		verifyKey: &signKey.PublicKey,
		bits:      bits,
	}

}

// NewRSAKeysFromBuffer is same as `NewKeysFromFile` _except_ that is uses a buffer
// to initialize the keys. Same constrains applies as with `NewKeysFromFile`.
func NewRSAKeysFromBuffer(pubKey, privKey []byte) *KeysImpl {

	k := keyFromBuffer(pubKey, privKey)

	if len(pubKey) > 0 {
		k.pubKeyID = "mem:///pubkey.bin"
	}

	if len(privKey) > 0 {
		k.privKeyID = "mem:///privkey.bin"
	}

	return k

}

// NewRSAKeysFromFile creates a new instance of a RSAKeypair compatible struct.
//
// Specify a public key path to a pem file. If the _privKeyPay_ is specified
// no _pubKeyPath_ is needed since it will extract the public key from the
// private one.
func NewRSAKeysFromFile(pubKeyPath, privKeyPath string) *KeysImpl {

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

	k := keyFromBuffer(verifyBytes, signBytes)

	if pubKeyPath != "" {
		k.pubKeyID = fmt.Sprintf("file://%s", pubKeyPath)
	}

	if privKeyPath != "" {
		k.privKeyID = fmt.Sprintf("file://%s", privKeyPath)
	}

	return k

}

// PublicKeyID is the identity of the public key. It may be a filepath or an _AWS ARN_.
func (k *KeysImpl) PublicKeyID() string {
	return k.pubKeyID
}

// PrivateKeyID is the identity of the private key. It may be a filepath or an _AWS ARN_.
func (k *KeysImpl) PrivateKeyID() string {
	return k.privKeyID
}

// Type returns the type of keypair is. For example _RSAKeyType_.
func (k *KeysImpl) Type() license.KeyType {
	return license.RSAKeyType
}

// KeyLength is the length of the key in bits, e.g. 382
func (k *KeysImpl) KeyLength() int {
	return k.bits
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

func keyFromBuffer(pubKey, privKey []byte) *KeysImpl {

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
