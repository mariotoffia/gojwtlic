package licutils

import "github.com/mariotoffia/gojwtlic/license"

// ToSigningMethod creates a JWT compatible singing method name
// based on the key type, e.g. RSA256.
func ToSigningMethod(keys license.RSAKeypair) string {

	return "RS256"

}
