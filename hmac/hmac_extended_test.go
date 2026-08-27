package hmac

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMd5(t *testing.T) {
	key := []byte("secret")
	msg := []byte("hello")
	result := Md5(key, msg)
	assert.Len(t, result.Bytes(), 16) // MD5 输出 16 bytes
}

func TestSha1(t *testing.T) {
	key := []byte("secret")
	msg := []byte("hello")
	result := Sha1(key, msg)
	assert.Len(t, result.Bytes(), 20) // SHA1 输出 20 bytes
}

func TestSha256(t *testing.T) {
	key := []byte("secret")
	msg := []byte("hello")
	result := Sha256(key, msg)
	assert.Len(t, result.Bytes(), 32) // SHA256 输出 32 bytes
}

func TestSha512(t *testing.T) {
	key := []byte("secret")
	msg := []byte("hello")
	result := Sha512(key, msg)
	assert.Len(t, result.Bytes(), 64) // SHA512 输出 64 bytes
}

func TestSm3(t *testing.T) {
	key := []byte("secret")
	msg := []byte("hello")
	result := Sm3(key, msg)
	assert.Len(t, result.Bytes(), 32) // SM3 输出 32 bytes
}

func TestByName(t *testing.T) {
	for _, name := range []string{"HMACMD5", "HMACSHA1", "HMACSHA224", "HMACSHA256", "HMACSHA384", "HMACSHA512", "HMACSM3"} {
		f, err := ByName(name)
		assert.NoError(t, err)
		assert.NotNil(t, f)
	}

	// 大小写不敏感
	f, err := ByName("hmacmd5")
	assert.NoError(t, err)
	assert.NotNil(t, f)

	// 不支持的
	_, err = ByName("INVALID")
	assert.Error(t, err)
}

func TestHashComparer_SignVerify(t *testing.T) {
	key := []byte("secret-key")
	c, err := New("HMACSHA256", key)
	assert.NoError(t, err)

	msg := []byte("hello world")
	sign, err := c.Sign(msg)
	assert.NoError(t, err)
	assert.NotEmpty(t, sign)

	// 验证正确
	assert.True(t, c.Verify(msg, sign))

	// 验证错误消息
	assert.False(t, c.Verify([]byte("wrong"), sign))

	// 验证错误签名
	wrongSign := make([]byte, len(sign))
	copy(wrongSign, sign)
	wrongSign[0] ^= 0xff
	assert.False(t, c.Verify(msg, wrongSign))

	// 验证长度不等的签名
	assert.False(t, c.Verify(msg, sign[:len(sign)-1]))
	assert.False(t, c.Verify(msg, append(append([]byte{}, sign...), 0x00)))
}

func TestHashComparer_DifferentKeys(t *testing.T) {
	msg := []byte("hello")

	c1, _ := New("HMACSHA256", []byte("key1"))
	c2, _ := New("HMACSHA256", []byte("key2"))

	sign1, _ := c1.Sign(msg)
	sign2, _ := c2.Sign(msg)

	// 不同 key 应该产生不同签名
	assert.NotEqual(t, sign1.Bytes(), sign2.Bytes())
}

func TestHashComparer_Deterministic(t *testing.T) {
	key := []byte("secret")
	msg := []byte("hello")

	c, _ := New("HMACSHA256", key)

	sign1, _ := c.Sign(msg)
	sign2, _ := c.Sign(msg)

	// 相同 key 和消息应该产生相同签名
	assert.Equal(t, sign1.Bytes(), sign2.Bytes())
}

func TestHmac_KnownVector(t *testing.T) {
	// RFC 4231 测试向量
	key, _ := hex.DecodeString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	data := []byte("Hi There")

	result := Sha256(key, data)
	expected := "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
	assert.Equal(t, expected, result.Hex())
}

func TestHmac_EmptyInput(t *testing.T) {
	key := []byte("secret")

	// 空消息
	result := Sha256(key, []byte{})
	assert.Len(t, result.Bytes(), 32)

	// 空 key
	result = Sha256([]byte{}, []byte("hello"))
	assert.Len(t, result.Bytes(), 32)
}
