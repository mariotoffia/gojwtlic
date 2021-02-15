package lickms

import "github.com/mariotoffia/gojwtlic/license"

type kmsJWT struct {
}

// NewSignCreator creates a new `license.JWTSignerCreator` that
// uses the _AWS KMS_ as the singer.
func NewSignCreator() license.JWTSignerCreator {

	return &kmsJWT{}
}

// SignCreate will Create a _JWT_ from the _info_ parameter and sign it.
// The returned string is a proper signed _JWT_.
func (kms *kmsJWT) SignCreate(info *license.FeatureInfo) (string, error) {

	return "", nil

}
