package crypto_test

// P3#24 审核修复：AsymConfig 扩展（根包半边）。
//
// 本轮只验证根包选项层的字段流转与参数合法性校验（工厂构造入口
// 应用选项即失败）；asym 子包对字段的消费接线由后续任务完成。

import (
	"crypto"
	"testing"

	rootcrypto "github.com/charlienet/go-crypto"
	_ "github.com/charlienet/go-crypto/engines" // 注册非对称引擎（NewAsymmetric 依赖）
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// apply 内联应用选项（与 asym 子包工厂同一模式：逐项应用，失败即返回）。
func apply(cfg *rootcrypto.AsymConfig, opts ...rootcrypto.AsymOption) error {
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return err
		}
	}
	return nil
}

// TestAsymConfig_RSAKeyBits WithRSAKeyBits：<2048 拒绝，0/>=2048 放行。
func TestAsymConfig_RSAKeyBits(t *testing.T) {
	cfg := &rootcrypto.AsymConfig{}
	require.NoError(t, apply(cfg, rootcrypto.WithRSAKeyBits(2048)))
	assert.Equal(t, 2048, cfg.RSAKeyBits)

	cfg = &rootcrypto.AsymConfig{}
	require.NoError(t, apply(cfg, rootcrypto.WithRSAKeyBits(4096)))
	assert.Equal(t, 4096, cfg.RSAKeyBits)

	// 0 → 走默认 2048（消费端归一）
	cfg = &rootcrypto.AsymConfig{}
	require.NoError(t, apply(cfg, rootcrypto.WithRSAKeyBits(0)))
	assert.Equal(t, 0, cfg.RSAKeyBits)

	// <2048 构造期拒绝
	cfg = &rootcrypto.AsymConfig{}
	err := apply(cfg, rootcrypto.WithRSAKeyBits(1024))
	assert.ErrorIs(t, err, rootcrypto.ErrInvalidAsymOption)
	assert.Zero(t, cfg.RSAKeyBits, "非法值时字段不应被写入")
}

// TestAsymConfig_ECDSACurve WithECDSACurve：白名单 P256/P384/P521，变体归一。
func TestAsymConfig_ECDSACurve(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"P256", "P256"},
		{"P-256", "P256"}, // 连字符变体
		{"p-256", "P256"}, // 大小写不敏感
		{"P384", "P384"},
		{"P-384", "P384"},
		{"P521", "P521"},
		{"P-521", "P521"},
		{"", ""}, // 默认 P256（消费端归一）
	}
	for _, c := range cases {
		cfg := &rootcrypto.AsymConfig{}
		require.NoError(t, apply(cfg, rootcrypto.WithECDSACurve(c.in)), "curve %q 应合法", c.in)
		assert.Equal(t, c.want, cfg.ECDSACurve, "curve %q 规范化存储", c.in)
	}

	// 白名单外拒绝（P-224 已禁用）
	cfg := &rootcrypto.AsymConfig{}
	err := apply(cfg, rootcrypto.WithECDSACurve("P-224"))
	assert.ErrorIs(t, err, rootcrypto.ErrInvalidAsymOption)
	err = apply(cfg, rootcrypto.WithECDSACurve("BRAINPOOL"))
	assert.ErrorIs(t, err, rootcrypto.ErrInvalidAsymOption)
}

// TestAsymConfig_Hash WithAsymHash：SHA-1/256/384/512 应用期白名单
// （SHA-1 判定延迟到构造期闸门）。
func TestAsymConfig_Hash(t *testing.T) {
	for _, h := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		cfg := &rootcrypto.AsymConfig{}
		require.NoError(t, apply(cfg, rootcrypto.WithAsymHash(h)), "hash %v 应合法", h)
		assert.Equal(t, h, cfg.Hash)
	}

	// 0 → 默认 SHA256（消费端归一）
	cfg := &rootcrypto.AsymConfig{}
	require.NoError(t, apply(cfg, rootcrypto.WithAsymHash(0)))
	assert.Zero(t, cfg.Hash)

	// SHA-1：应用期放行写入配置（判定延迟到构造期闸门，见
	// asymmetric_insecure_gate_test.go）
	cfg = &rootcrypto.AsymConfig{}
	require.NoError(t, apply(cfg, rootcrypto.WithAsymHash(crypto.SHA1)))
	assert.Equal(t, crypto.SHA1, cfg.Hash)

	// 白名单外拒绝
	for _, h := range []crypto.Hash{crypto.MD5, crypto.MD5SHA1} {
		cfg := &rootcrypto.AsymConfig{}
		err := apply(cfg, rootcrypto.WithAsymHash(h))
		assert.ErrorIs(t, err, rootcrypto.ErrInvalidAsymOption, "hash %v 应拒绝", h)
		assert.Zero(t, cfg.Hash, "非法值时字段不应被写入")
	}
}

// TestAsymConfig_SM2UID WithSM2UID：拷贝保存，修改原切片不影响配置。
func TestAsymConfig_SM2UID(t *testing.T) {
	uid := []byte("custom-uid-1234567")
	cfg := &rootcrypto.AsymConfig{}
	require.NoError(t, apply(cfg, rootcrypto.WithSM2UID(uid)))
	assert.Equal(t, uid, cfg.SM2UID)

	// 修改原切片：配置内副本不受影响
	uid[0] = 'X'
	assert.Equal(t, []byte("custom-uid-1234567"), cfg.SM2UID)
}

// TestAsymConfig_SM2LegacyCiphertext WithSM2LegacyCiphertext：置位遗留格式。
func TestAsymConfig_SM2LegacyCiphertext(t *testing.T) {
	cfg := &rootcrypto.AsymConfig{}
	require.NoError(t, apply(cfg, rootcrypto.WithSM2LegacyCiphertext()))
	assert.True(t, cfg.SM2LegacyCipher)

	// 默认 false（新认证格式 C1C3C2）
	cfg = &rootcrypto.AsymConfig{}
	require.NoError(t, apply(cfg))
	assert.False(t, cfg.SM2LegacyCipher)
}

// TestAsymConfig_ThroughNewAsymmetric 选项经工厂构造入口应用（校验在
// 构造链路内生效）：非法参数在 NewAsymmetric 即被拒绝。（引擎需已注册，
// 由 engines blank import 提供。）
func TestAsymConfig_ThroughNewAsymmetric(t *testing.T) {
	// 非法 RSA 位数 → 构造入口拒绝
	_, err := rootcrypto.NewAsymmetric(rootcrypto.RSA, rootcrypto.WithRSAKeyBits(1024))
	assert.ErrorIs(t, err, rootcrypto.ErrInvalidAsymOption)

	// 非法曲线 → 构造入口拒绝
	_, err = rootcrypto.NewAsymmetric(rootcrypto.ECDSA, rootcrypto.WithECDSACurve("P-224"))
	assert.ErrorIs(t, err, rootcrypto.ErrInvalidAsymOption)

	// SHA-1 现经选项期放行（应用期白名单），由 SM2 消费侧拒绝
	// （SM2 固定使用 SM3 摘要，不支持自定义签名哈希）
	_, err = rootcrypto.NewAsymmetric(rootcrypto.SM2, rootcrypto.WithAsymHash(crypto.SHA1))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not support custom asymmetric hash")
}
