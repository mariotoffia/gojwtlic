package licjwt

import (
	"fmt"
	"testing"
	"time"

	"github.com/mariotoffia/gojwtlic/license"
	"github.com/mariotoffia/gojwtlic/license/licjwt/licbuiltin"
)

func TestToJSONIndent(t *testing.T) {

	generator := NewGeneratorBuilder().
		Audience("https://api.valmatics.se").
		ClientID("valmatics2.x").
		ClientSecret("SecretFromAWSCognito").
		Issuer("https://api.valmatics.se/licmgr").
		LicenseLength(time.Hour * 24 * 365 * 10 /*~10 year*/)

	fi, err := generator.CreateFeatureInfo().
		Feature("simulator").
		Feature("regulate").
		Feature("ui").
		Feature("settings").
		WithSubject("hobbe.nisse@azcam.net").
		/* add feature called settings for analog & digital in / out :: rw */
		FeatureDetails(map[string]license.Feature{
			"settings": &license.FeatureImpl{
				Claims: map[string]interface{}{
					"access": "rw",
					"ao":     true,
					"do":     true,
					"ai":     true,
					"di":     true,
				},
			},
		}).ToJSONIndent()

	if err != nil {
		panic(err)
	}

	fmt.Println(string(fi))
}

func TestGenerateSingleFeature(t *testing.T) {

	generator := NewGeneratorBuilderWithSigner(
		licbuiltin.NewSignCreator(licbuiltin.NewRSAKeys(4096), "RS256"),
	).
		Audience("https://api.valmatics.se").
		ClientID("valmatics2.x").
		ClientSecret("SecretFromAWSCognito").
		Issuer("https://api.valmatics.se/licmgr").
		LicenseLength(time.Hour * 24 * 365 * 10 /*~10 year*/)

	license := generator.Create(
		generator.CreateFeatureInfo().
			Feature("simulator").
			Feature("regulate").
			Feature("ui").
			Feature("settings").
			WithSubject("hobbe.nisse@azcam.net").
			/* add feature called settings for analog & digital in / out :: rw */
			FeatureDetails(map[string]license.Feature{
				"settings": &license.FeatureImpl{
					Claims: map[string]interface{}{
						"access": "rw",
						"ao":     true,
						"do":     true,
						"ai":     true,
						"di":     true,
					},
				},
			}),
	)

	fmt.Println(license)
}
