package kdf

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==================== Scrypt ====================

func TestScrypt_RFC7914Vectors(t *testing.T) {
	// RFC 7914 §12 Test vector 1：空口令 + 空盐
	dk, err := Scrypt(16, 1, 1, []byte(""), []byte(""), 64)
	require.NoError(t, err)
	expected1, _ := hex.DecodeString("77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906")
	assert.Equal(t, expected1, dk, "RFC 7914 vector 1")

	// RFC 7914 §12 Test vector 2
	dk, err = Scrypt(1024, 8, 16, []byte("password"), []byte("NaCl"), 64)
	require.NoError(t, err)
	expected2, _ := hex.DecodeString("fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640")
	assert.Equal(t, expected2, dk, "RFC 7914 vector 2")
}

func TestScrypt_Deterministic(t *testing.T) {
	password := []byte("password")
	salt := []byte("random-salt-16bytes")

	dk1, err := Scrypt(1<<15, 8, 1, password, salt, 32)
	require.NoError(t, err)
	dk2, err := Scrypt(1<<15, 8, 1, password, salt, 32)
	require.NoError(t, err)
	assert.Equal(t, dk1, dk2)

	// 不同口令产生不同输出
	dk3, _ := Scrypt(1<<15, 8, 1, []byte("other"), salt, 32)
	assert.False(t, bytes.Equal(dk1, dk3))
}

func TestScrypt_InvalidParams(t *testing.T) {
	pw, salt := []byte("password"), []byte("salt")

	// N 必须为 >1 的 2 的幂
	_, err := Scrypt(0, 8, 1, pw, salt, 32)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "N must be > 1 and a power of 2")

	_, err = Scrypt(1, 8, 1, pw, salt, 32)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "N must be > 1 and a power of 2")

	_, err = Scrypt(24, 8, 1, pw, salt, 32) // 非 2 的幂
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "N must be > 1 and a power of 2")

	// r / p / keyLen 必须为正
	_, err = Scrypt(16, 0, 1, pw, salt, 32)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "r must be positive")

	_, err = Scrypt(16, 8, 0, pw, salt, 32)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "p must be positive")

	_, err = Scrypt(16, 8, 1, pw, salt, 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "keyLen must be positive")
}

func TestScrypt_DoSLimit(t *testing.T) {
	pw, salt := []byte("password"), []byte("salt")

	// 超限：N=2^23（单参数即破上限）
	_, err := Scrypt(1<<23, 8, 1, pw, salt, 32)
	assert.ErrorIs(t, err, ErrKDFParamsTooLarge)

	// 超限：乘积 2^15 * 8 * 17 > 2^22
	_, err = Scrypt(1<<15, 8, 17, pw, salt, 32)
	assert.ErrorIs(t, err, ErrKDFParamsTooLarge)

	// 超限：r*p 组合超限（r=2^20, p=2^3 → 2^23）
	_, err = Scrypt(1<<15, 1<<20, 8, pw, salt, 32)
	assert.ErrorIs(t, err, ErrKDFParamsTooLarge)

	// 边界：乘积恰为 2^22（OWASP 组合各维度 4 倍余量之内），合法
	dk, err := Scrypt(1<<15, 8, 16, pw, salt, 32)
	require.NoError(t, err)
	assert.Len(t, dk, 32)
}

func TestScrypt_OwaspRecommendedParams(t *testing.T) {
	// OWASP 2024 推荐组合：N=2^15, r=8, p=1（文档示例）
	dk, err := Scrypt(1<<15, 8, 1, []byte("password"), []byte("random-salt-16bytes"), 32)
	require.NoError(t, err)
	assert.Len(t, dk, 32)
}
