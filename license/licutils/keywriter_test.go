package licutils

import (
	"os"
	"testing"

	"github.com/mariotoffia/gojwtlic/license/licjwt/licbuiltin"
	"github.com/stretchr/testify/assert"
)

func TestWritePublicAndPrivateKey(t *testing.T) {

	keys := licbuiltin.NewRSAKeys(4096)

	defer func() {

		os.Remove("testing-private.pem")
		os.Remove("testing-public.pem")

	}()

	err := WriteRSAKeys(keys, "testing", "")

	assert.Equal(t, nil, err)

}
