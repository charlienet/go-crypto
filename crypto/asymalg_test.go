package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestAsymmetricAlgorithm_StringParseRoundtrip String()/Parse 往返：
// 六项预定义枚举全部满足 ParseAsymmetricAlgorithm(a.String()) == a。
func TestAsymmetricAlgorithm_StringParseRoundtrip(t *testing.T) {
	for _, a := range []AsymmetricAlgorithm{RSA, ECDSA, ED25519, SM2, ECDH, X25519} {
		assert.Equal(t, a, ParseAsymmetricAlgorithm(a.String()), "algorithm=%v", a)
	}
}

// TestAsymmetricAlgorithm_StringRoundtrip 自定义值 String() 原样返回。
func TestAsymmetricAlgorithm_StringRoundtrip(t *testing.T) {
	assert.Equal(t, "X", (AsymmetricAlgorithm("X")).String())
}

// TestAsymmetricAlgorithm_IsPredefined IsPredefined()：六预定义值 true，其余 false。
func TestAsymmetricAlgorithm_IsPredefined(t *testing.T) {
	for _, a := range []AsymmetricAlgorithm{RSA, ECDSA, ED25519, SM2, ECDH, X25519} {
		assert.True(t, a.IsPredefined(), "algorithm=%v", a)
	}

	for _, a := range []AsymmetricAlgorithm{"", "ML-KEM", "SM3", "INVALID"} {
		assert.False(t, a.IsPredefined(), "algorithm=%q", a)
	}
}

// TestParseAsymmetricAlgorithm_CaseInsensitive Parse 大小写兼容：
// 预定义算法经 NormalizeAlgorithm 归一化（大小写不敏感）后映射到预定义常量。
func TestParseAsymmetricAlgorithm_CaseInsensitive(t *testing.T) {
	for _, name := range []string{"rsa", "RSA", "Rsa"} {
		assert.Equal(t, RSA, ParseAsymmetricAlgorithm(name), "name=%s", name)
	}

	for _, name := range []string{"sm2", "Sm2", "SM2"} {
		assert.Equal(t, SM2, ParseAsymmetricAlgorithm(name), "name=%s", name)
	}

	for _, name := range []string{"ed25519", "Ed25519", "ED25519"} {
		assert.Equal(t, ED25519, ParseAsymmetricAlgorithm(name), "name=%s", name)
	}
}

// TestParseAsymmetricAlgorithm_Unknown 非预定义名称原样返回（不做归一化、不校验可用性）。
func TestParseAsymmetricAlgorithm_Unknown(t *testing.T) {
	assert.Equal(t, AsymmetricAlgorithm("ml-kem-1024"), ParseAsymmetricAlgorithm("ml-kem-1024"))
	assert.Equal(t, AsymmetricAlgorithm("ML-KEM"), ParseAsymmetricAlgorithm("ML-KEM"))
	assert.Equal(t, AsymmetricAlgorithm(""), ParseAsymmetricAlgorithm(""))
}

// TestAsymmetricAlgorithm_ConstantsMatch 常量与 alg.go 字符串常量一致性（单点维护，杜绝双处硬编码）。
func TestAsymmetricAlgorithm_ConstantsMatch(t *testing.T) {
	assert.Equal(t, AlgorithmRSA, string(RSA))
	assert.Equal(t, AlgorithmECDSA, string(ECDSA))
	assert.Equal(t, AlgorithmED25519, string(ED25519))
	assert.Equal(t, AlgorithmSM2, string(SM2))
	assert.Equal(t, AlgorithmECDH, string(ECDH))
	assert.Equal(t, AlgorithmX25519, string(X25519))
}

// TestAsymmetricAlgorithm_CustomExtension 类型转换扩展：
// 第三方自定义算法名可直接经类型转换选中，String() 原样返回、不视为预定义。
func TestAsymmetricAlgorithm_CustomExtension(t *testing.T) {
	custom := AsymmetricAlgorithm("ML-KEM")
	assert.Equal(t, "ML-KEM", custom.String())
	assert.False(t, custom.IsPredefined())
	assert.Equal(t, custom, ParseAsymmetricAlgorithm("ML-KEM"))
}
