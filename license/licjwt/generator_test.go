package licjwt

import (
	"fmt"
	"testing"
	"time"

	"github.com/mariotoffia/gojwtlic/license"
)

func TestGenerateSingleFeature(t *testing.T) {

	generator := NewGenerator(NewKeys(4096), "RS256").
		Audience("https://api.valmatics.se").
		ClientID("valmatics2.x").
		ClientSecret("SecretFromAWSCognito").
		Issuer("https://api.valmatics.se/licmgr").
		LicenseLength(time.Hour * 24 * 365 * 10 /*10 year*/)

	license := generator.Create(
		generator.CreateFeatureInfo().
			Feature("simulator").
			Feature("regulate").
			Feature("ui").
			WithSubject("hobbe.nisse@azcam.net").
			FeatureDetails(map[string]license.Feature{
				"settings": &license.FeatureImpl{
					Details: map[string]interface{}{
						"AO": true,
						"DO": true,
						"AI": true,
						"DI": true,
					},
				},
			}),
	)

	fmt.Println(license)
}
