package crypto_test

import (
	"testing"

	"github.com/charlienet/go-crypto"
	"github.com/stretchr/testify/assert"
)

// TestKeySource_Override 测试密钥源覆盖行为
func TestKeySource_Override(t *testing.T) {
	key1 := make([]byte, 16)
	key2 := make([]byte, 16)
	// 填充不同值
	for i := range key1 {
		key1[i] = 0x01
	}
	for i := range key2 {
		key2[i] = 0x02
	}

	pt := []byte("test payload for override behavior")
	alg, mode := crypto.AES128, crypto.GCM

	// 第二个 WithKey 覆盖第一个
	// 用 key2 能解密，用 key1 不能
	ct, err := crypto.Encrypt(alg, mode, pt,
		crypto.WithKey(key1),
		crypto.WithKey(key2))
	assert.NoError(t, err)

	// 用 key2 应该能成功解密
	got, err := crypto.Decrypt(alg, mode, ct, crypto.WithKey(key2))
	assert.NoError(t, err)
	assert.Equal(t, pt, got)

	// 用 key1 应该不能解密
	_, err = crypto.Decrypt(alg, mode, ct, crypto.WithKey(key1))
	assert.Error(t, err) // 应该认证失败或格式错误
}

// TestMixedKeySource_Override 测试不同类型密钥源之间的覆盖行为
func TestMixedKeySource_Override(t *testing.T) {
	key1 := make([]byte, 16)
	key2 := make([]byte, 16)
	for i := range key1 {
		key1[i] = 0x03
	}
	for i := range key2 {
		key2[i] = 0x04
	}
	pt := []byte("test mixed key source override")
	alg, mode := crypto.AES128, crypto.GCM

	// WithKey(key2) 覆盖 WithKey(key1)
	ct, err := crypto.Encrypt(alg, mode, pt,
		crypto.WithKey(key1),
		crypto.WithKey(key2))
	assert.NoError(t, err)

	// 用 key2 应该能解密
	got, err := crypto.Decrypt(alg, mode, ct, crypto.WithKey(key2))
	assert.NoError(t, err)
	assert.Equal(t, pt, got)

	// 用原始 key1 应该不能解密
	_, err = crypto.Decrypt(alg, mode, ct, crypto.WithKey(key1))
	assert.Error(t, err)
}
