package licjwt

import (
	"time"

	"github.com/google/uuid"
	"github.com/mariotoffia/gojwtlic/license"
)

// GeneratorJWT is compatible with the Generator interface
type GeneratorJWT struct {
	creator      license.JWTSignerCreator
	lasterr      error
	audience     string
	issuer       string
	licenselen   int64
	clientID     string
	clientSecret string
}

// NewGeneratorBuilder creates a new `GeneratorJWT` using `NewGenerator` and wraps it using
// the `license.GeneratorBuilder` to allow for builder style configuration.
func NewGeneratorBuilder() *license.GeneratorBuilder {
	return license.NewGenerator(NewGenerator())
}

// NewGeneratorBuilderWithSigner is the same as `NewGeneratorBuilderWithSigner` but sets the
// signer creator directly
func NewGeneratorBuilderWithSigner(creator license.JWTSignerCreator) *license.GeneratorBuilder {

	g := NewGenerator()
	g.SetSignerCreator(creator)

	return license.NewGenerator(g)

}

// NewGenerator creates a new `license.Generator`
//
// If not specify signing it tries to use sensible defaults. The signing is the
// JWT compatible signing string such as "RS256".
func NewGenerator() *GeneratorJWT {

	return &GeneratorJWT{}

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
func (g *GeneratorJWT) Audience(aud string) {
	g.audience = aud
}

// Issuer sets the default issuer
func (g *GeneratorJWT) Issuer(iss string) {
	g.issuer = iss
}

// LicenseLength sets the default length gives "now + t = expires" in
// unix 32 bit epoch format.
func (g *GeneratorJWT) LicenseLength(t time.Duration) {
	g.licenselen = int64(t / time.Second)
}

// ClientID sets the default client id
func (g *GeneratorJWT) ClientID(id string) {
	g.clientID = id
}

// ClientSecret sets the default secret.
func (g *GeneratorJWT) ClientSecret(secret string) {
	g.clientSecret = secret
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

// SetSignerCreator enables signing and generaton of a proper _JWT_ when
// invoking the `Create(*FeatureInfo)` in this instance.
func (g *GeneratorJWT) SetSignerCreator(creator license.JWTSignerCreator) {
	g.creator = creator
}

// Create generates a new license.
func (g *GeneratorJWT) Create(info *license.FeatureInfo) string {

	if nil == g.creator {

		data, err := info.ToJSON()

		if err != nil {
			g.lasterr = err
			return ""
		}

		return string(data)
	}

	ss, err := g.creator.SignCreate(info)

	if err != nil {
		g.lasterr = err
		return ""
	}

	return ss

}
