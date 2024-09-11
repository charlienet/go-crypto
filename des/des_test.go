package des_test

import (
	"testing"

	"github.com/charlienet/go-crypto/des"
	"github.com/charlienet/go-misc/random"
	"github.com/stretchr/testify/assert"
)

func TestECB(t *testing.T) {

}

func TestCBC(t *testing.T) {
	key, _ := random.RandBytes(24)
	d, _ := des.CBC(key)

	enctypted, err := d.Encrypt([]byte("123"))
	assert.Nil(t, err)

	decrypted, err := d.Decrypt(enctypted)
	assert.Nil(t, err)

	assert.Equal(t, []byte("123"), decrypted)
	_ = enctypted
}
