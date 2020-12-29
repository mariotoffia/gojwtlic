package licutils

import (
	"os"
	"testing"

	"github.com/mariotoffia/gojwtlic/license/licjwt"
	"github.com/stretchr/testify/assert"
)

func TestWritePublicAndPrivateKey(t *testing.T) {

	keys := licjwt.NewKeys(4096)

	defer func() {

		os.Remove("testing-private.pem")
		os.Remove("testing-public.pem")

	}()

	err := WriteRSAKeys(keys, "testing", "")

	assert.Equal(t, nil, err)

}
