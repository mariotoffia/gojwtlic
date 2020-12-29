package license

import (
	"crypto/rsa"
	"io/ioutil"
	"log"

	jwt "github.com/dgrijalva/jwt-go"
)

const (
	privKeyPath = "private-key.pem"
	pubKeyPath  = "public-key.pem"
)

func fatal(err error) {
	if err != nil {
		log.Fatal(err)
		panic(err)
	}
}

// RSAKeypair holds public and private _RSA_ key pair
type RSAKeypair interface {
	PublicKey() *rsa.PublicKey
	PrivateKey() *rsa.PrivateKey
}

// KeysImpl implements the RSAKeypair interface.
type KeysImpl struct {
	verifyKey *rsa.PublicKey
	signKey   *rsa.PrivateKey
}

// NewKeysImpl creates a new instance of a RSAKeypair compatible struct.
func NewKeysImpl(privKeyPath, pubKeyPath string) *KeysImpl {

	signBytes, err := ioutil.ReadFile(privKeyPath)
	fatal(err)

	signKey, err := jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	fatal(err)

	verifyBytes, err := ioutil.ReadFile(pubKeyPath)
	fatal(err)

	verifyKey, err := jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	fatal(err)

	return &KeysImpl{
		signKey:   signKey,
		verifyKey: verifyKey,
	}
}

// PublicKey returns the public key portion
func (k *KeysImpl) PublicKey() *rsa.PublicKey {
	return k.verifyKey
}

// PrivateKey returns the private key portion
func (k *KeysImpl) PrivateKey() *rsa.PrivateKey {
	return k.signKey
}
