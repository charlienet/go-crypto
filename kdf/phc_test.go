package kdf

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==================== PasswordHash ====================

func TestPasswordHash_Verify_RoundTrip(t *testing.T) {
	password := []byte("user-password")

	ph, err := PasswordHash(password, nil)
	require.NoError(t, err)

	// 正确口令验证通过
	ok, err := PasswordVerify(ph, password)
	require.NoError(t, err)
	assert.True(t, ok)

	// 错误口令验证失败
	ok, err = PasswordVerify(ph, []byte("wrong-password"))
	require.NoError(t, err)
	assert.False(t, ok)

	// 参数与 salt 相同则同口令确定性输出：重复验证结果稳定
	ok, err = PasswordVerify(ph, password)
	require.NoError(t, err)
	assert.True(t, ok)

	// 每次哈希盐值随机：两次输出不同，但均可验证通过
	ph2, err := PasswordHash(password, nil)
	require.NoError(t, err)
	assert.NotEqual(t, ph, ph2)
	ok, err = PasswordVerify(ph2, password)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestPasswordHash_Schema(t *testing.T) {
	ph, err := PasswordHash([]byte("password"), nil)
	require.NoError(t, err)

	// PHC 标准格式 + Raw StdEncoding（无 padding，无 '='）
	re := regexp.MustCompile(`^\$argon2id\$v=19\$m=65536,t=3,p=4\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$`)
	assert.Regexp(t, re, ph)

	// salt 16 字节 -> 22 字符，hash 32 字节 -> 43 字符（无 padding 的长度特征）
	parts := strings.Split(ph, "$")
	assert.Len(t, parts, 6)
	assert.Len(t, parts[4], 22)
	assert.Len(t, parts[5], 43)
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	require.NoError(t, err)
	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	require.NoError(t, err)
	assert.Len(t, salt, 16)
	assert.Len(t, hash, 32)
}

func TestPasswordHash_MatchesArgon2id(t *testing.T) {
	// 一致性断言：PHC 层的派生语义必须与 Argon2id 完全一致。
	// 从 PasswordHash 输出中恢复 salt/参数，用 Argon2id 重算并对比。
	password := []byte("password")
	opts := &PasswordHashOptions{MemoryKiB: 8192, Iterations: 2, Parallelism: 2, KeyLen: 16, SaltLen: 16}

	ph, err := PasswordHash(password, opts)
	require.NoError(t, err)
	parts := strings.Split(ph, "$")
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	require.NoError(t, err)
	hashInPHC, err := base64.RawStdEncoding.DecodeString(parts[5])
	require.NoError(t, err)

	dk, err := Argon2id(password, salt, 2, 8192, 2, 16)
	require.NoError(t, err)
	assert.Equal(t, hashInPHC, dk, "PHC 层必须与 Argon2id 派生语义一致")

	// 手工构造固定 salt 的 PHC 串，验证可被解析且校验通过
	fixedSalt := []byte("fixed-salt-16xx")
	fixedDK, err := Argon2id(password, fixedSalt, 3, 64*1024, 4, 32)
	require.NoError(t, err)
	handBuilt := fmt.Sprintf("$argon2id$v=19$m=65536,t=3,p=4$%s$%s",
		base64.RawStdEncoding.EncodeToString(fixedSalt),
		base64.RawStdEncoding.EncodeToString(fixedDK))
	ok, err := PasswordVerify(handBuilt, password)
	require.NoError(t, err)
	assert.True(t, ok)
	ok, err = PasswordVerify(handBuilt, []byte("wrong"))
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestPasswordHash_EmptyPassword(t *testing.T) {
	// 口令存储场景拒绝空口令：避免与"未设置口令"的哨兵值混淆，
	// 且空口令可在毫秒级枚举，属于弱凭据。
	_, err := PasswordHash(nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "password must not be empty")

	_, err = PasswordHash([]byte{}, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "password must not be empty")
}

func TestPasswordHash_InvalidOptions(t *testing.T) {
	pw := []byte("password")

	// 写侧算法白名单仅 argon2id
	_, err := PasswordHash(pw, &PasswordHashOptions{Algorithm: "scrypt"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported password hash algorithm")

	_, err = PasswordHash(pw, &PasswordHashOptions{Algorithm: "bcrypt"})
	assert.Error(t, err)

	// 负参数拒绝
	_, err = PasswordHash(pw, &PasswordHashOptions{MemoryKiB: -1})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "memoryKiB must be positive")

	_, err = PasswordHash(pw, &PasswordHashOptions{Iterations: -1})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "iterations must be positive")

	_, err = PasswordHash(pw, &PasswordHashOptions{Parallelism: -1})
	assert.Error(t, err)

	_, err = PasswordHash(pw, &PasswordHashOptions{KeyLen: -1})
	assert.Error(t, err)

	_, err = PasswordHash(pw, &PasswordHashOptions{SaltLen: -1})
	assert.Error(t, err)

	// 派生上限：超大 m/t/p 拒绝（与 Scrypt 同款 DoS 纪律）
	_, err = PasswordHash(pw, &PasswordHashOptions{MemoryKiB: 1 << 25})
	assert.ErrorIs(t, err, ErrKDFParamsTooLarge)

	_, err = PasswordHash(pw, &PasswordHashOptions{Iterations: 1000})
	assert.ErrorIs(t, err, ErrKDFParamsTooLarge)

	_, err = PasswordHash(pw, &PasswordHashOptions{Parallelism: 1000})
	assert.ErrorIs(t, err, ErrKDFParamsTooLarge)

	// 输出/盐长度上限
	_, err = PasswordHash(pw, &PasswordHashOptions{KeyLen: 4096})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "keyLen too large")

	_, err = PasswordHash(pw, &PasswordHashOptions{SaltLen: 4096})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "saltLen too large")
}

// ==================== PasswordVerify ====================

func TestPasswordVerify_InvalidString(t *testing.T) {
	validSalt := base64.RawStdEncoding.EncodeToString(make([]byte, 16))
	validHash := base64.RawStdEncoding.EncodeToString(make([]byte, 32))

	cases := []string{
		"", // 空串
		"argon2id$v=19$m=65536,t=3,p=4$" + validSalt + "$" + validHash,             // 缺前导 $
		"$argon2id$v=19$m=65536,t=3,p=4$" + validSalt,                              // 缺 hash 段
		"$argon2id$v=19$m=65536,t=3,p=4$$" + validHash,                             // 空 salt 段
		"$argon2id$v=19$m=65536,t=3,p=4$" + validSalt + "$" + validHash + "$extra", // 多余段
		"$argon2id$v=18$m=65536,t=3,p=4$" + validSalt + "$" + validHash,            // 版本不支持
		"$argon2id$v=19$m=65536,t=3$" + validSalt + "$" + validHash,                // 缺 p 参数
		"$argon2id$v=19$m=65536,t=3,p=4,x=1$" + validSalt + "$" + validHash,        // 未知参数
		"$argon2id$v=19$m=-1,t=3,p=4$" + validSalt + "$" + validHash,               // 负参数
		"$argon2id$v=19$m=abc,t=3,p=4$" + validSalt + "$" + validHash,              // 非数值
		"$argon2id$v=19$m=65536,t=3,p=4$!!!$" + validHash,                          // 坏 b64 salt
		"$argon2id$v=19$m=65536,t=3,p=4$" + validSalt + "$!!!",                     // 坏 b64 hash
		"$argon2id$v=19$m=65536,t=3,p=4$" + validSalt + "$" + validHash + "=",      // b64 带 padding
		"$bcrypt$2a$10$" + validSalt + "$" + validHash,                             // 未知算法
	}
	for _, tc := range cases {
		_, err := PasswordVerify(tc, []byte("password"))
		assert.Error(t, err, "case: %q", tc)
	}
}

func TestPasswordVerify_DoSLimit(t *testing.T) {
	pw := []byte("password")
	validSalt := base64.RawStdEncoding.EncodeToString(make([]byte, 16))
	validHash := base64.RawStdEncoding.EncodeToString(make([]byte, 32))

	// 恶意串：m=2^31 远超 1 GiB 上限（须在派生前拒绝，防存储文件 DoS）
	malicious := "$argon2id$v=19$m=2147483648,t=3,p=4$" + validSalt + "$" + validHash
	_, err := PasswordVerify(malicious, pw)
	assert.ErrorIs(t, err, ErrKDFParamsTooLarge)

	// t / p 超限
	_, err = PasswordVerify("$argon2id$v=19$m=65536,t=1000000,p=4$"+validSalt+"$"+validHash, pw)
	assert.ErrorIs(t, err, ErrKDFParamsTooLarge)

	_, err = PasswordVerify("$argon2id$v=19$m=65536,t=3,p=1024$"+validSalt+"$"+validHash, pw)
	assert.ErrorIs(t, err, ErrKDFParamsTooLarge)

	// hash 段超长（1025 字节，超 phcMaxKeyLen）拒绝
	hugeHash := base64.RawStdEncoding.EncodeToString(make([]byte, 1025))
	_, err = PasswordVerify("$argon2id$v=19$m=65536,t=3,p=4$"+validSalt+"$"+hugeHash, pw)
	assert.ErrorIs(t, err, ErrKDFParamsTooLarge)
}

func TestPasswordVerify_ScryptBranch(t *testing.T) {
	// scrypt 仅验证侧保留（读旧库存储串），写侧统一 argon2id
	password := []byte("password")
	salt := []byte("scrypt-salt-16x")
	dk, err := Scrypt(1<<15, 8, 4, password, salt, 32)
	require.NoError(t, err)

	ph := fmt.Sprintf("$scrypt$ln=15,r=8,p=4$%s$%s",
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(dk))

	ok, err := PasswordVerify(ph, password)
	require.NoError(t, err)
	assert.True(t, ok)

	ok, err = PasswordVerify(ph, []byte("wrong"))
	require.NoError(t, err)
	assert.False(t, ok)

	// 恶意 scrypt 串：ln=21, r=4, p=1 -> N*r*p = 2^23 > 2^22，拒绝
	valid32 := base64.RawStdEncoding.EncodeToString(make([]byte, 32))
	_, err = PasswordVerify("$scrypt$ln=21,r=4,p=1$"+valid32+"$"+valid32, password)
	assert.ErrorIs(t, err, ErrKDFParamsTooLarge)

	// scrypt 串缺少 p 参数
	_, err = PasswordVerify("$scrypt$ln=15,r=8$"+valid32+"$"+valid32, password)
	assert.Error(t, err)
}

// ==================== PasswordNeedsRehash ====================

func TestPasswordNeedsRehash(t *testing.T) {
	password := []byte("password")

	// 默认策略哈希 → 不需要重哈希
	ph, err := PasswordHash(password, nil)
	require.NoError(t, err)
	need, err := PasswordNeedsRehash(ph, nil)
	require.NoError(t, err)
	assert.False(t, need)

	// 任一参数与当前策略不一致 → 需要重哈希（参数升级钩子）
	need, err = PasswordNeedsRehash(ph, &PasswordHashOptions{MemoryKiB: 128 * 1024})
	require.NoError(t, err)
	assert.True(t, need)

	need, err = PasswordNeedsRehash(ph, &PasswordHashOptions{Iterations: 4})
	require.NoError(t, err)
	assert.True(t, need)

	need, err = PasswordNeedsRehash(ph, &PasswordHashOptions{Parallelism: 8})
	require.NoError(t, err)
	assert.True(t, need)

	need, err = PasswordNeedsRehash(ph, &PasswordHashOptions{KeyLen: 64})
	require.NoError(t, err)
	assert.True(t, need)

	// scrypt 串（仅验证保留）→ 建议升级到 argon2id
	salt := []byte("scrypt-salt-16x")
	dk, err := Scrypt(1<<15, 8, 4, password, salt, 32)
	require.NoError(t, err)
	scryptPHC := fmt.Sprintf("$scrypt$ln=15,r=8,p=4$%s$%s",
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(dk))
	need, err = PasswordNeedsRehash(scryptPHC, nil)
	require.NoError(t, err)
	assert.True(t, need)

	// 格式非法 → 错误
	_, err = PasswordNeedsRehash("not-a-phc-string", nil)
	assert.Error(t, err)
}
