package license

import "time"

// Generator do genereate licenses that is encoded into a JWT
//
// The JWT is defined in https://tools.ietf.org/html/rfc7797 and
// it's best practices is defined in https://tools.ietf.org/html/rfc8725,
// of the base RFC https://tools.ietf.org/html/rfc7519.
type Generator interface {
	// Error will return the last error, if any.
	Error() error
	// ClearError will clear any error that is present
	ClearError()
	// Audience sets the default audience
	Audience(aud string)
	// Issuer sets the default issuer
	Issuer(iss string)
	// LicenseLength sets the default length gives "now + t = expires" in
	// unix 32 bit epoch format.
	LicenseLength(t time.Duration)
	// ClientID sets the default client id
	ClientID(id string)
	// ClientSecret sets the default secret.
	ClientSecret(secret string)
	// CreateFeatureInfo creates a `license.FeatureInfo` with default
	// values set.
	//
	// Caller needs to update the `FeatureInfo` before calling `Create()`.
	CreateFeatureInfo() *FeatureInfo
	// Create generates a new license.
	Create(info *FeatureInfo) string
}

// GeneratorBuilder is a wrapper of a single ´Generator` that
// implements the fluent builder pattern.
type GeneratorBuilder struct {
	gen Generator
}

// NewGenerator creates a new `GeneratorBuilder` by wrapping
// the in parameter _gen_.
func NewGenerator(gen Generator) *GeneratorBuilder {

	return &GeneratorBuilder{
		gen: gen,
	}

}

// Error will return the last error, if any.
func (g *GeneratorBuilder) Error() error {
	return g.gen.Error()
}

// ClearError will clear any error that is present
func (g *GeneratorBuilder) ClearError() *GeneratorBuilder {
	g.gen.ClearError()
	return g
}

// Audience sets the default audience
func (g *GeneratorBuilder) Audience(aud string) *GeneratorBuilder {
	g.gen.Audience(aud)
	return g
}

// Issuer sets the default issuer
func (g *GeneratorBuilder) Issuer(iss string) *GeneratorBuilder {
	g.gen.Issuer(iss)
	return g
}

// LicenseLength sets the default length gives "now + t = expires" in
// unix 32 bit epoch format.
func (g *GeneratorBuilder) LicenseLength(t time.Duration) *GeneratorBuilder {
	g.gen.LicenseLength(t)
	return g
}

// ClientID sets the default client id
func (g *GeneratorBuilder) ClientID(id string) *GeneratorBuilder {
	g.gen.ClientID(id)
	return g
}

// ClientSecret sets the default secret.
func (g *GeneratorBuilder) ClientSecret(secret string) *GeneratorBuilder {
	g.gen.ClientSecret(secret)
	return g
}

// CreateFeatureInfo creates a `license.FeatureInfo` with default
// values set.
//
// Caller needs to update the `FeatureInfo` before calling `Create()`.
func (g *GeneratorBuilder) CreateFeatureInfo() *FeatureInfo {
	return g.gen.CreateFeatureInfo()
}

// Create generates a new license.
func (g *GeneratorBuilder) Create(info *FeatureInfo) string {
	return g.gen.Create(info)
}
