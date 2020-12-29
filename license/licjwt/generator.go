package licjwt

import (
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/mariotoffia/gojwtlic/license"
)

// GeneratorJWT is compatible with the Generator interface
type GeneratorJWT struct {
	keys         license.RSAKeypair
	signing      string
	lasterr      error
	audience     string
	issuer       string
	licenselen   int64
	clientID     string
	clientSecret string
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

// Audience sets the default audience
func (g *GeneratorJWT) Audience(aud string) *GeneratorJWT {
	g.audience = aud
	return g
}

// Issuer sets the default issuer
func (g *GeneratorJWT) Issuer(iss string) *GeneratorJWT {
	g.issuer = iss
	return g
}

// LicenseLength sets the default length gives "now + t = expires" in
// unix 32 bit epoch format.
func (g *GeneratorJWT) LicenseLength(t time.Duration) *GeneratorJWT {
	g.licenselen = int64(t * time.Second)
	return g
}

// ClientID sets the default client id
func (g *GeneratorJWT) ClientID(id string) *GeneratorJWT {
	g.clientID = id
	return g
}

// ClientSecret sets the default secret.
func (g *GeneratorJWT) ClientSecret(secret string) *GeneratorJWT {
	g.clientSecret = secret
	return g
}

// CreateFeatureInfo creates a `license.FeatureInfo` with default
// values set.
//
// Caller needs to update the `FeatureInfo` before calling `Create()`.
func (g *GeneratorJWT) CreateFeatureInfo() *license.FeatureInfo {

	licenseID, err := uuid.NewUUID()
	if err != nil {

		g.lasterr = err
		return &license.FeatureInfo{}

	}

	now := time.Now().Unix()

	return &license.FeatureInfo{
		BaseInfo: license.BaseInfo{
			Audience:  g.audience,
			Issuer:    g.issuer,
			Expires:   now + g.licenselen,
			Issued:    now,
			NotBefore: now,
			LicenseID: licenseID.String(),
		},
		OauthInfo: license.OauthInfo{
			ClientID:     g.clientID,
			ClientSecret: g.clientSecret,
		},
		FeatureMap: map[string]license.Feature{},
	}

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
