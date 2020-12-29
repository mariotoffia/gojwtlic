package licjwt

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/mariotoffia/gojwtlic/license"
)

// GeneratorJWT is compatible with the Generator interface
type GeneratorJWT struct {
	keys    license.RSAKeypair
	signing string
	lasterr error
}

// NewGenerator creates a new `license.Generator`
//
// If not specify signing it tries to use sensible defaults. The signing is the
// JWT compatible signing string such as "RS256".
func NewGenerator(keys license.RSAKeypair, signing string) *GeneratorJWT {

	if keys == nil {
		panic("No keys specified")
	}

	if signing == "" {
		signing = "RS256"
	}

	return &GeneratorJWT{
		keys:    keys,
		signing: signing,
	}

}

// Error will return the last error, if any.
func (g *GeneratorJWT) Error() error {
	return g.lasterr
}

// ClearError will clear any error that is present
func (g *GeneratorJWT) ClearError() {
	g.lasterr = nil
}

// Create generates a new license.
func (g *GeneratorJWT) Create(info *license.FeatureInfo) string {

	token := jwt.NewWithClaims(jwt.GetSigningMethod(g.signing), info)

	ss, err := token.SignedString(g.keys.PrivateKey())

	if err != nil {

		g.lasterr = err

	}

	return ss

}
