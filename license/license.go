package license

// Generator do genereate licenses that is encoded into a JWT
//
// The JWT is defined in https://tools.ietf.org/html/rfc7797 and
// it's best practices is defined in https://tools.ietf.org/html/rfc8725,
// of the base RFC https://tools.ietf.org/html/rfc7519.
type Generator interface {
}

// Validator can validate licenses
type Validator interface {
}

// Info contains all license information
type Info struct {
	// ClientID is the OAuth 2.0 client id used to communicate with the cloud services
	//
	// Defined as "client_id" in https://www.rfc-editor.org/rfc/rfc8693.html#name-client_id-client-identifier
	ClientID string `json:"client_id,omitempty"`
	// ClientSecret is the OAuth 2.0 client secret used to communicate with the cloud services
	//
	// Defines as "client_secret" in the license and should never leave the system. If this is omitted, the
	// system itself embeds the client secret and may only use ClientID. This is usually a cryptographic safe
	// random with the client id uniquely identify a license owner or a group of licenses.
	ClientSecret string `json:"client_secret,omitempty"`
	// audience is the base address of the license / system resource  e.g. https://api.valmatics.com
	//
	// Defined as "aud" in https://tools.ietf.org/html/rfc7519
	Audience string `json:"aud,omitempty"`
	// Issuer specifies the principal that issued the license e.g. "https://api.valmatics.com/2.0.0/licsrv"
	//
	// Defined as "iss" in https://tools.ietf.org/html/rfc7519
	Issuer string `json:"iss,omitempty"`
	// Subject is the principal that is the subject of the license e.g. "8c059ae6-dee7-4145-a6dc-d2820b4adf70" or
	// "nisse@hult.se".
	//
	// It may be anything that can be used to uniquely distinguish the license e.g. "Mörtvikens Såg AB".
	// Defined as "sub" in https://tools.ietf.org/html/rfc7519.
	Subject string `json:"sub,omitempty"`
	// Expires is the number of seconds when the license expires based on unix 32 bit epoch time (
	// from 1970-01-01T00:00:00Z) see RFC 3339 for more details. For example 1609231906 is 2020-12-29T08:51:46Z.
	//
	// Defined as "exp" in https://tools.ietf.org/html/rfc7519.
	Expires int64 `json:"exp,omitempty"`
	// Issued at is a unix 32 bit epoch time when the license was issued.
	//
	// Defined as "iat" in https://tools.ietf.org/html/rfc7519.
	Issued int64 `json:"iat,omitempty"`
	// NotBefore at is a unix 32 bit epoch time when the license is activated (this may be in future!).
	//
	// Defined as "nbf" in https://tools.ietf.org/html/rfc7519.
	NotBefore int64 `json:"nbf,omitempty"`
	// LicenseID is a unique license id for each license generated (even if same license is generated more than once)
	// e.g. "8c059ae6-dee7-4145-a6dc-d2820b4adf70".
	//
	// This can be used to blacklist if a certain license has been compromised (e.g. distributed) but the legal owner
	// still want to run their system safely. Hence re-generate a new license, blacklist the old license id and the newly
	// generated license can execute on same terms as before and the old license is no longer valid.
	//
	// NOTE: The old license is still valid in a off-line scenario, this may only be detected in a online scenario or if
	// the system downloads a "blacklist" for off-line blacklist support.
	//
	// Defined as "jti" in https://tools.ietf.org/html/rfc7519.
	LicenseID string `json:"jti,omitempty"`
	// Features is a space separated string of the features that this license grants. For example "simulator regulation ui"
	//
	// If you need to be more specific which precise claims you grant the license use the
	// Defines as "scope" in https://www.rfc-editor.org/rfc/rfc8693.html#name-scope-scopes-claim
	Features string `json:"scope,omitempty"`
}

// LicImpl is compatible with the Generator and Validator interface
//
// Usually separated, but for this contrived example combined.
type LicImpl struct {
	keys RSAKeypair
}

// NewLicenseManager creates a new `Generator` & `Validator`
func NewLicenseManager(keys RSAKeypair) *LicImpl {

	if keys == nil {
		panic("No keys specified")
	}

	return &LicImpl{
		keys: keys,
	}

}

// Generate will generate a new license.
func (l *LicImpl) Generate(info Info) string {

	//fmt.Sprintf("%v", claims)
	return ""
}
