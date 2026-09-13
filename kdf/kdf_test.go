package kdf

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==================== HKDF ====================

func TestHKDF_SHA256(t *testing.T) {
	// RFC 5869 Test Case 1
	ikm, _ := hex.DecodeString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt, _ := hex.DecodeString("000102030405060708090a0b0c")
	info, _ := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")

	key, err := HKDF("SHA-256", ikm, salt, info, 42)
	require.NoError(t, err)

	expected, _ := hex.DecodeString("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
	assert.Equal(t, expected, key)
}

func TestHKDF_SHA512(t *testing.T) {
	secret := []byte("secret")
	salt := []byte("salt")
	info := []byte("info")

	key, err := HKDF("SHA-512", secret, salt, info, 32)
	require.NoError(t, err)
	assert.Len(t, key, 32)

	// 相同输入产生相同输出
	key2, _ := HKDF("SHA-512", secret, salt, info, 32)
	assert.Equal(t, key, key2)

	// 不同 info 产生不同输出
	key3, _ := HKDF("SHA-512", secret, salt, []byte("other"), 32)
	assert.NotEqual(t, key, key3)
}

func TestHKDF_NilSaltAndInfo(t *testing.T) {
	secret := []byte("secret")
	key, err := HKDF("SHA-256", secret, nil, nil, 16)
	require.NoError(t, err)
	assert.Len(t, key, 16)
}

func TestHKDF_UnsupportedHash(t *testing.T) {
	_, err := HKDF("MD5", []byte("secret"), nil, nil, 16)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported hash algorithm")
}

func TestHKDF_OutputTooLong(t *testing.T) {
	// SHA-256 最大输出 255 * 32 = 8160 字节
	_, err := HKDF("SHA-256", []byte("secret"), nil, nil, 8161)
	assert.Error(t, err)
}

// ==================== PBKDF2 ====================

func TestPBKDF2_Basic(t *testing.T) {
	password := []byte("password")
	salt := []byte("salt")

	key, err := PBKDF2(password, salt, 100000, 16)
	require.NoError(t, err)
	assert.Len(t, key, 16)

	// 相同输入产生相同输出
	key2, _ := PBKDF2(password, salt, 100000, 16)
	assert.Equal(t, key, key2)

	// 不同密码产生不同输出
	key3, _ := PBKDF2([]byte("other"), salt, 100000, 16)
	assert.NotEqual(t, key, key3)
}

func TestPBKDF2_InvalidParams(t *testing.T) {
	_, err := PBKDF2([]byte("password"), []byte("salt"), 0, 16)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "iterations must be positive")

	_, err = PBKDF2([]byte("password"), []byte("salt"), 100000, 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "keyLen must be positive")
}

func TestPBKDF2WithHash_SHA512(t *testing.T) {
	password := []byte("password")
	salt := []byte("salt")

	key, err := PBKDF2WithHash("SHA-512", password, salt, 100000, 32)
	require.NoError(t, err)
	assert.Len(t, key, 32)
}

func TestPBKDF2WithHash_UnsupportedHash(t *testing.T) {
	_, err := PBKDF2WithHash("MD5", []byte("password"), []byte("salt"), 100000, 16)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported hash algorithm")
}

// ==================== Argon2id ====================

func TestArgon2id_Basic(t *testing.T) {
	password := []byte("password")
	salt := []byte("some-salt-value")

	key, err := Argon2id(password, salt, 3, 64*1024, 4, 16)
	require.NoError(t, err)
	assert.Len(t, key, 16)

	// 相同输入产生相同输出
	key2, _ := Argon2id(password, salt, 3, 64*1024, 4, 16)
	assert.Equal(t, key, key2)

	// 不同密码产生不同输出
	key3, _ := Argon2id([]byte("other"), salt, 3, 64*1024, 4, 16)
	assert.NotEqual(t, key, key3)
}

func TestArgon2id_InvalidParams(t *testing.T) {
	password := []byte("password")
	salt := []byte("salt")

	// 表驱动病态组合：全部须在进入 argon2.IDKey 前被拦截返回 error（永不 panic）。
	// 契约固化：x/crypto v0.54.0 的 IDKey 在 memory < 8*threads 时并不 panic，
	// 而是静默产出非 RFC 标准密钥（参考实现 phc-winner-argon2 此时返回
	// ARGON2_MEMORY_TOO_SMALL）——本包的 memory ≥ 8*threads 下界即为拦截该行为。
	cases := []struct {
		name        string
		time        uint32
		memory      uint32
		threads     uint8
		keyLen      int
		wantErrSubs string
	}{
		{"time=0", 0, 64 * 1024, 4, 16, "time must be positive"},
		{"memory=0", 3, 0, 4, 16, "memory must be positive"},
		{"threads=0", 3, 64 * 1024, 0, 16, "threads must be positive"},
		{"keyLen=0", 3, 64 * 1024, 4, 0, "keyLen must be positive"},
		{"keyLen<0", 3, 64 * 1024, 4, -1, "keyLen must be positive"},
		// memory < 8*threads 下界（原会静默产出非标准密钥）
		{"mem1<thr8", 3, 1, 8, 32, "memory must be at least 8*threads"},
		{"mem7<thr1", 3, 7, 1, 32, "memory must be at least 8*threads"},
		{"mem31<thr4", 3, 31, 4, 32, "memory must be at least 8*threads"},
		{"mem0_thr8", 1, 0, 8, 32, "memory must be positive"},
		// 上界（防内存 DoS / 输出误用）
		{"keyLen>1MiB", 1, 8, 1, 1<<30 - 1, "keyLen exceeds 1 MiB limit"},
		{"mem>2GiB", 3, 1 << 22, 1, 32, "memory exceeds 2 GiB limit"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			// 无 panic 断言：固化"公开 API 永不 panic、以 error 表达失败"契约。
			require.NotPanics(t, func() {
				_, err = Argon2id(password, salt, tc.time, tc.memory, tc.threads, tc.keyLen)
			})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErrSubs)
		})
	}
}

// TestArgon2id_KeyDProductionParams 固化 keyd 生产组合（64MiB/t=3/p=1）行为不变：
// 该组合远低于本包上界（memory 1<<21 KiB、keyLen 1<<20 B），修复后仍须正常派生。
func TestArgon2id_KeyDProductionParams(t *testing.T) {
	password := []byte("password")
	salt := []byte("some-salt-value")

	key, err := Argon2id(password, salt, 3, 64*1024, 1, 32)
	require.NoError(t, err)
	assert.Len(t, key, 32)
}

func TestArgon2idDefault(t *testing.T) {
	password := []byte("password")
	salt := []byte("some-salt-value")

	key, err := Argon2idDefault(password, salt, 16)
	require.NoError(t, err)
	assert.Len(t, key, 16)
}

// ==================== DeriveKey ====================

func TestDeriveKey_Basic(t *testing.T) {
	password := []byte("password")
	salt := []byte("some-salt-value")

	key, err := DeriveKey(password, salt, 16)
	require.NoError(t, err)
	assert.Len(t, key, 16)

	// 相同输入产生相同输出
	key2, _ := DeriveKey(password, salt, 16)
	assert.Equal(t, key, key2)
}

func TestDeriveKey_InvalidParams(t *testing.T) {
	_, err := DeriveKey([]byte("password"), []byte("salt"), 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "keyLen must be positive")

	_, err = DeriveKey([]byte("password"), nil, 16)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "salt must not be empty")

	_, err = DeriveKey([]byte("password"), []byte{}, 16)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "salt must not be empty")
}

// ==================== 集成测试 ====================

func TestDeriveKey_ThenEncrypt(t *testing.T) {
	// 模拟真实场景：从密码派生密钥，然后加密
	password := []byte("user-password")
	salt := []byte("random-salt-value")
	plaintext := []byte("secret message")

	// 派生 AES-128 密钥
	key, err := DeriveKey(password, salt, 16)
	require.NoError(t, err)

	// 验证密钥长度适合 AES-128
	assert.Len(t, key, 16)

	// 模拟加密（这里只验证密钥可用）
	// 实际使用时：crypto.Encrypt(crypto.AES128, crypto.GCM, plaintext, crypto.WithKey(key))
	_ = plaintext
}

func TestHKDF_KeyExpansion(t *testing.T) {
	// 模拟密钥扩展场景：从主密钥派生多个子密钥
	masterKey := bytes.Repeat([]byte{0x42}, 32)

	encKey, err := HKDF("SHA-256", masterKey, nil, []byte("encryption"), 16)
	require.NoError(t, err)

	authKey, err := HKDF("SHA-256", masterKey, nil, []byte("authentication"), 32)
	require.NoError(t, err)

	// 不同用途产生不同密钥
	assert.NotEqual(t, encKey, authKey[:16])
	assert.Len(t, encKey, 16)
	assert.Len(t, authKey, 32)
}
