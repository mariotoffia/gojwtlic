package licutils

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mariotoffia/gojwtlic/license"
)

// WriteRSAKeys writes out the rsa key pair onto the filepath.
//
// The name is prefixed onto the file names _name-private.pem_ and
// _name-public.pem_.
// If any error occurs it is returned.
func WriteRSAKeys(keys license.RSAKeypair, name, fp string) error {

	if keys == nil {
		return fmt.Errorf("must specify keys to write")
	}

	privateKey := keys.PrivateKey()

	if privateKey != nil {

		privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)

		privateKeyBlock := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privateKeyBytes,
		}

		privatePem, err := os.Create(
			filepath.Join(fp,
				fmt.Sprintf("%s-private.pem", name),
			),
		)

		if err != nil {
			return err
		}

		if err = pem.Encode(privatePem, privateKeyBlock); err != nil {
			return err
		}

	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(keys.PublicKey())

	if err != nil {
		return err
	}

	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	publicPem, err := os.Create(
		filepath.Join(fp,
			fmt.Sprintf("%s-public.pem", name),
		),
	)

	if err != nil {
		return err
	}

	return pem.Encode(publicPem, publicKeyBlock)

}
