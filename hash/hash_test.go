package hash

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMd5(t *testing.T) {
	result := Md5([]byte("hello"))
	assert.Equal(t, "5d41402abc4b2a76b9719d911017c592", result.Hex())
}

func TestSha1(t *testing.T) {
	result := Sha1([]byte("hello"))
	assert.Equal(t, "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d", result.Hex())
}

func TestSha256(t *testing.T) {
	result := Sha256([]byte("hello"))
	assert.Equal(t, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", result.Hex())
}

func TestSha512(t *testing.T) {
	result := Sha512([]byte("hello"))
	expected := "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043"
	assert.Equal(t, expected, result.Hex())
}

func TestSm3(t *testing.T) {
	result := Sm3([]byte("hello"))
	// SM3 输出 32 bytes
	assert.Len(t, result.Bytes(), 32)
}

func TestMurmur3(t *testing.T) {
	result := Murmur3([]byte("hello"))
	assert.NotEqual(t, uint64(0), result)
}

func TestXXhash(t *testing.T) {
	result := XXhash([]byte("hello"))
	assert.Len(t, result, 8) // xxhash 输出 8 bytes
}

func TestXXHashUint64(t *testing.T) {
	result := XXHashUint64([]byte("hello"))
	assert.NotEqual(t, uint64(0), result)
}

func TestFnv32(t *testing.T) {
	result := Fnv32([]byte("hello"))
	assert.NotEqual(t, uint32(0), result)
}

func TestFnv64(t *testing.T) {
	result := Fnv64([]byte("hello"))
	assert.NotEqual(t, uint64(0), result)
}

func TestByName(t *testing.T) {
	// 测试支持的哈希函数
	for _, name := range []string{"MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "SM3"} {
		f, err := ByName(name)
		assert.NoError(t, err)
		assert.NotNil(t, f)
	}

	// 测试大小写不敏感
	f, err := ByName("md5")
	assert.NoError(t, err)
	assert.NotNil(t, f)

	// 测试不支持的哈希函数：错误消息须包含支持列表（P2 改进）
	_, err = ByName("INVALID")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported hash function")
	assert.Contains(t, err.Error(), `"INVALID"`)
	assert.Contains(t, err.Error(), "supported:")
	assert.Contains(t, err.Error(), "sha256")
}

func TestHashComparer(t *testing.T) {
	c, err := New("MD5")
	assert.NoError(t, err)

	msg := []byte("hello")
	sign, err := c.Sign(msg)
	assert.NoError(t, err)

	// 验证正确
	assert.True(t, c.Verify(msg, sign))

	// 验证错误消息
	assert.False(t, c.Verify([]byte("wrong"), sign))
}

func TestHashComparer_VerifyConstantTime(t *testing.T) {
	c, err := New("MD5")
	assert.NoError(t, err)

	msg := []byte("hello")
	sign, err := c.Sign(msg)
	assert.NoError(t, err)

	// 正确摘要返回 true
	assert.True(t, c.Verify(msg, sign))

	// 错误摘要返回 false
	wrongSign := make([]byte, len(sign))
	copy(wrongSign, sign)
	wrongSign[0] ^= 0xff
	assert.False(t, c.Verify(msg, wrongSign))

	// 长度不等的 target 返回 false
	assert.False(t, c.Verify(msg, sign[:len(sign)-1]))
	assert.False(t, c.Verify(msg, append(append([]byte{}, sign...), 0x00)))
}

func TestHash_EmptyInput(t *testing.T) {
	// 测试空输入
	result := Md5([]byte{})
	expected, _ := hex.DecodeString("d41d8cd98f00b204e9800998ecf8427e")
	assert.Equal(t, expected, result.Bytes())
}
