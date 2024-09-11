package sm4_test

import (
	"testing"

	"github.com/charlienet/go-crypto/sm4"
	"github.com/charlienet/go-misc/random"
	"github.com/stretchr/testify/assert"
)

func TestECBEnctypt(t *testing.T) {
	key, _ := random.RandBytes(sm4.BlockSize)
	value := []byte("1111111111111112")

	encrypter := sm4.ECB(key)
	encrypted, err := encrypter.Encrypt(value)
	assert.Nil(t, err)

	t.Log(encrypted)

	ret, err := sm4.ECB(key).Dectypt(encrypted)
	assert.Nil(t, err)

	assert.Equal(t, value, ret)
}

func TestCBC(t *testing.T) {
	key, _ := random.RandBytes(sm4.BlockSize)
	iv, _ := random.RandBytes(sm4.BlockSize)
	value := []byte("1111111111111112")

	encrypter, _ := sm4.CBC(key, sm4.WithIV(iv))

	encrypted, err := encrypter.Encrypt(value)
	assert.Nil(t, err)

	t.Log(encrypted)

	ret, err := encrypter.Dectypt(encrypted)
	assert.Nil(t, err)

	assert.Equal(t, value, ret)
}

func TestCBCNoIV(t *testing.T) {
	key, _ := random.RandBytes(sm4.BlockSize)
	value := []byte("1111111111111112")

	encrypter, _ := sm4.CBC(key)

	encrypted, err := encrypter.Encrypt(value)
	assert.Nil(t, err)

	t.Log(encrypted)

	ret, err := encrypter.Dectypt(encrypted)
	assert.Nil(t, err)

	assert.Equal(t, value, ret)
}
