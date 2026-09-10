package crypto_test

// RSA SHA-1 构造期安全闸门 + PKCS#1 v1.5 签名填充（遗留系统互操作）。
//
// 覆盖：
//   - 选项置位：WithRSAPKCS1v15Signing / WithAsymInsecureAlgorithms 独立置位
//   - 默认拒绝：RSA + WithAsymHash(SHA1) 未 opt-in → ErrInsecureAlgorithm
//   - 顺序无关：闸门与哈希选项任意排列，构造期判定结果一致
//   - 目标往返：v1.5 + SHA-1 全 opt-in 后 Sign/Verify 成功（含独立验签实例）
//   - 标准库互操作：本库 v1.5 签名 ↔ rsa.SignPKCS1v15/VerifyPKCS1v15 双向
//   - padding 切换不走安全闸门：v1.5 + SHA-256 无需 AllowInsecure
//   - padding confusion 防线：跨 padding 验签双向返回 false
//   - 边界 RSA-only：ECDSA（asymHash 兜底）/SM2（消费侧）无 SHA-1 放行通道
//   - 加密不受污染：v1.5 + SHA-1 实例 Encrypt/Decrypt 仍为 OAEP
//
// 风格对齐 insecure_gate_test.go；错误判定统一走 errors.Is 可识别的
// ErrInsecureAlgorithm / ErrInvalidAsymOption 哨兵。

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"sync"
	"testing"

	rootcrypto "github.com/charlienet/go-crypto"
	_ "github.com/charlienet/go-crypto/engines" // 注册非对称引擎（NewAsymmetric 依赖）
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 包级共享 2048 位测试密钥：懒生成一次，供多数用例经对象注入复用，
// 避免每个用例各生成一把 2048 位密钥拖慢测试（同 asym/rsa_test.go 模式）。
var (
	gateRSAKeyOnce sync.Once
	gateRSAKeyPrv  *rsa.PrivateKey
	gateRSAKeyErr  error
)

// gateTestRSAKey 返回懒生成的 2048 位测试私钥。
func gateTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	gateRSAKeyOnce.Do(func() {
		gateRSAKeyPrv, gateRSAKeyErr = rsa.GenerateKey(rand.Reader, 2048)
	})
	if gateRSAKeyErr != nil {
		t.Fatalf("生成测试 RSA 密钥失败: %v", gateRSAKeyErr)
	}
	return gateRSAKeyPrv
}

// sha1Digest 计算消息的 SHA-1 摘要（标准库互操作断言用）。
func sha1Digest(msg []byte) []byte {
	h := crypto.SHA1.New()
	h.Write(msg)
	return h.Sum(nil)
}

// 全 opt-in 组合（v1.5 + SHA-1）与仅 SHA-1 闸门组合的选项基组。
func v15SHA1Opts(extra ...rootcrypto.AsymOption) []rootcrypto.AsymOption {
	base := []rootcrypto.AsymOption{
		rootcrypto.WithRSAPKCS1v15Signing(),
		rootcrypto.WithAsymHash(crypto.SHA1),
		rootcrypto.WithAsymInsecureAlgorithms(),
	}
	return append(base, extra...)
}

// TestAsymInsecureGate_Options 两个新选项各自正确置位配置字段且互不连带。
func TestAsymInsecureGate_Options(t *testing.T) {
	cfg := &rootcrypto.AsymConfig{}
	require.NoError(t, apply(cfg, rootcrypto.WithRSAPKCS1v15Signing()))
	assert.True(t, cfg.RSASignPKCS1v15)
	assert.False(t, cfg.AllowInsecure, "padding 切换不应置位安全闸门")

	cfg = &rootcrypto.AsymConfig{}
	require.NoError(t, apply(cfg, rootcrypto.WithAsymInsecureAlgorithms()))
	assert.True(t, cfg.AllowInsecure)
	assert.False(t, cfg.RSASignPKCS1v15, "闸门放行不应改变 padding 默认（PSS）")

	// 默认零值：两者均关闭
	cfg = &rootcrypto.AsymConfig{}
	require.NoError(t, apply(cfg))
	assert.False(t, cfg.RSASignPKCS1v15)
	assert.False(t, cfg.AllowInsecure)
}

// TestAsymInsecureGate_DefaultReject SHA-1 默认拒绝：无 WithAsymInsecureAlgorithms()
// 时构造期返回 ErrInsecureAlgorithm（errors.Is 可判定），含 padding 组合。
func TestAsymInsecureGate_DefaultReject(t *testing.T) {
	_, err := rootcrypto.NewAsymmetric(rootcrypto.RSA, rootcrypto.WithAsymHash(crypto.SHA1))
	assert.ErrorIs(t, err, rootcrypto.ErrInsecureAlgorithm, "RSA+SHA-1 默认应拒绝")

	// v1.5 选项属格式开关不走闸门，SHA-1 仍须独立 opt-in
	_, err = rootcrypto.NewAsymmetric(rootcrypto.RSA,
		rootcrypto.WithRSAPKCS1v15Signing(),
		rootcrypto.WithAsymHash(crypto.SHA1),
	)
	assert.ErrorIs(t, err, rootcrypto.ErrInsecureAlgorithm, "v1.5+SHA-1 未放行闸门仍应拒绝")
}

// TestAsymInsecureGate_OrderIndependent 闸门与哈希选项两种排列结果一致
// （判定延迟到构造期，顺序无关）。
func TestAsymInsecureGate_OrderIndependent(t *testing.T) {
	prv := gateTestRSAKey(t)

	// 排列 1：先 WithAsymHash 后闸门
	a, err := rootcrypto.NewAsymmetric(rootcrypto.RSA,
		rootcrypto.WithRSAPKCS1v15Signing(),
		rootcrypto.WithAsymHash(crypto.SHA1),
		rootcrypto.WithAsymInsecureAlgorithms(),
		rootcrypto.WithPrivateKeyObject(prv),
	)
	require.NoError(t, err, "排列 1（哈希→闸门）应构造成功")

	// 排列 2：先闸门后 WithAsymHash
	b, err := rootcrypto.NewAsymmetric(rootcrypto.RSA,
		rootcrypto.WithAsymInsecureAlgorithms(),
		rootcrypto.WithAsymHash(crypto.SHA1),
		rootcrypto.WithRSAPKCS1v15Signing(),
		rootcrypto.WithPrivateKeyObject(prv),
	)
	require.NoError(t, err, "排列 2（闸门→哈希）应构造成功")

	// 功能一致：两种排列构造的实例签名互相验签通过（同 padding 同 hash）
	msg := []byte("order independent opt-in")
	sigA, err := a.Sign(msg)
	require.NoError(t, err)
	sigB, err := b.Sign(msg)
	require.NoError(t, err)
	assert.True(t, b.Verify(msg, sigA), "排列 2 实例应接受排列 1 实例签名")
	assert.True(t, a.Verify(msg, sigB), "排列 1 实例应接受排列 2 实例签名")
}

// TestAsymInsecureGate_TargetRoundtrip 目标场景：v1.5 + 闸门 + SHA-1 全 opt-in
// 后 GenerateKey → Sign → Verify 往返成功；另起独立验签实例（同配置、
// WithPublicKey 注入导出公钥）验证通过。
func TestAsymInsecureGate_TargetRoundtrip(t *testing.T) {
	signer, err := rootcrypto.NewAsymmetric(rootcrypto.RSA, v15SHA1Opts()...)
	require.NoError(t, err)

	_, err = signer.GenerateKey()
	require.NoError(t, err)

	msg := []byte("legacy interop signature roundtrip")
	sig, err := signer.Sign(msg)
	require.NoError(t, err)
	require.NotEmpty(t, sig)
	assert.True(t, signer.Verify(msg, sig), "同实例 Sign/Verify 应通过")

	// 独立验签实例：同配置 + 导出公钥（base64 字符串注入路径）
	pubB64, err := signer.ExportPublicKey()
	require.NoError(t, err)
	verifier, err := rootcrypto.NewAsymmetric(rootcrypto.RSA, append(v15SHA1Opts(),
		rootcrypto.WithPublicKey(pubB64))...)
	require.NoError(t, err)
	assert.True(t, verifier.Verify(msg, sig), "独立同配置实例应验证通过")

	// 篡改消息应验证失败
	assert.False(t, verifier.Verify(append(msg, '!'), sig), "篡改消息不应通过验证")
}

// TestAsymInsecureGate_StdlibInterop 标准库互操作强断言：本库 v1.5+SHA-1 签名
// 被 rsa.VerifyPKCS1v15(pub, crypto.SHA1, digest, sig) 接受；标准库
// rsa.SignPKCS1v15 的签名被本库同配置实例 Verify 接受。
// （风格参考 asym/rsa_test.go 的 TestRSAStandardPSSInterop。）
func TestAsymInsecureGate_StdlibInterop(t *testing.T) {
	prv := gateTestRSAKey(t)
	signer, err := rootcrypto.NewAsymmetric(rootcrypto.RSA, append(v15SHA1Opts(),
		rootcrypto.WithPrivateKeyObject(prv))...)
	require.NoError(t, err)

	msg := []byte("pkcs1 v1.5 sha1 interop across implementations")
	digest := sha1Digest(msg)

	// 方向 1：本库签名 → 标准库（独立实现）验签
	projSig, err := signer.Sign(msg)
	require.NoError(t, err)
	err = rsa.VerifyPKCS1v15(&prv.PublicKey, crypto.SHA1, digest, projSig)
	assert.NoError(t, err, "标准库 rsa.VerifyPKCS1v15 应接受本库 v1.5+SHA-1 签名")

	// 方向 2：标准库签名 → 本库验签
	stdSig, err := rsa.SignPKCS1v15(rand.Reader, prv, crypto.SHA1, digest)
	require.NoError(t, err)
	assert.True(t, signer.Verify(msg, stdSig), "本库 Verify 应接受标准库 rsa.SignPKCS1v15 签名")
}

// TestAsymInsecureGate_PKCS1v15SecureHash padding 切换不走安全闸门：
// v1.5 + SHA-256（不带 WithAsymInsecureAlgorithms）往返成功——带显式
// WithAsymHash(SHA256) 与不带（走默认）两种。
func TestAsymInsecureGate_PKCS1v15SecureHash(t *testing.T) {
	prv := gateTestRSAKey(t)
	cases := []struct {
		name string
		opts []rootcrypto.AsymOption
	}{
		{"仅v1.5默认SHA256", []rootcrypto.AsymOption{
			rootcrypto.WithRSAPKCS1v15Signing(),
			rootcrypto.WithPrivateKeyObject(prv),
		}},
		{"v1.5显式SHA256", []rootcrypto.AsymOption{
			rootcrypto.WithRSAPKCS1v15Signing(),
			rootcrypto.WithAsymHash(crypto.SHA256),
			rootcrypto.WithPrivateKeyObject(prv),
		}},
	}
	msg := []byte("padding switch is not a security gate")
	for _, c := range cases {
		s, err := rootcrypto.NewAsymmetric(rootcrypto.RSA, c.opts...)
		require.NoError(t, err, "%s 无闸门应构造成功", c.name)
		sig, err := s.Sign(msg)
		require.NoError(t, err, "%s Sign 失败", c.name)
		assert.True(t, s.Verify(msg, sig), "%s Verify 应通过", c.name)
	}
}

// TestAsymInsecureGate_PaddingConfusionRejected padding confusion 防线：
// 同密钥同 SHA-1 下，v1.5 实例的签名被 PSS 配置实例 Verify → false；
// 反向亦 false（无自动回退探测）。
func TestAsymInsecureGate_PaddingConfusionRejected(t *testing.T) {
	prv := gateTestRSAKey(t)

	v15, err := rootcrypto.NewAsymmetric(rootcrypto.RSA, append(v15SHA1Opts(),
		rootcrypto.WithPrivateKeyObject(prv))...)
	require.NoError(t, err)

	pss, err := rootcrypto.NewAsymmetric(rootcrypto.RSA,
		rootcrypto.WithAsymHash(crypto.SHA1),
		rootcrypto.WithAsymInsecureAlgorithms(),
		rootcrypto.WithPrivateKeyObject(prv),
	)
	require.NoError(t, err, "SHA-1+PSS 经闸门应构造成功")

	msg := []byte("padding confusion defense")
	sigV15, err := v15.Sign(msg)
	require.NoError(t, err)
	sigPSS, err := pss.Sign(msg)
	require.NoError(t, err)

	assert.False(t, pss.Verify(msg, sigV15), "v1.5 签名不应被 PSS 配置实例接受")
	assert.False(t, v15.Verify(msg, sigPSS), "PSS 签名不应被 v1.5 配置实例接受")

	// 同 padding 对照排除密钥因素
	assert.True(t, v15.Verify(msg, sigV15), "v1.5 签名应被同配置实例接受")
	assert.True(t, pss.Verify(msg, sigPSS), "PSS 签名应被同配置实例接受")
}

// TestAsymInsecureGate_SHA1WithPSS SHA-1 放行不绑定 padding：仅闸门 + SHA-1
// （不带 v1.5，默认 PSS）往返成功。
func TestAsymInsecureGate_SHA1WithPSS(t *testing.T) {
	prv := gateTestRSAKey(t)
	s, err := rootcrypto.NewAsymmetric(rootcrypto.RSA,
		rootcrypto.WithAsymHash(crypto.SHA1),
		rootcrypto.WithAsymInsecureAlgorithms(),
		rootcrypto.WithPrivateKeyObject(prv),
	)
	require.NoError(t, err)

	msg := []byte("sha1 over PSS still reachable")
	sig, err := s.Sign(msg)
	require.NoError(t, err)
	assert.True(t, s.Verify(msg, sig), "SHA-1+PSS 往返应成功")
}

// TestAsymInsecureGate_ECDSANoChannel 边界 RSA-only：ECDSA 无 SHA-1 放行通道，
// 带 WithAsymInsecureAlgorithms() 仍拒绝，且错误不是 ErrInsecureAlgorithm
// （asymHash 白名单兜底拒绝）。
func TestAsymInsecureGate_ECDSANoChannel(t *testing.T) {
	_, err := rootcrypto.NewAsymmetric(rootcrypto.ECDSA,
		rootcrypto.WithAsymHash(crypto.SHA1),
		rootcrypto.WithAsymInsecureAlgorithms(),
	)
	require.Error(t, err, "ECDSA 不应有 SHA-1 放行通道")
	assert.False(t, errors.Is(err, rootcrypto.ErrInsecureAlgorithm),
		"ECDSA+SHA-1 拒绝应来自 asymHash 兜底，而非 ErrInsecureAlgorithm 闸门")
}

// TestAsymInsecureGate_SM2RejectedWithGate SM2 固定 SM3 摘要：带闸门 + SHA-1
// 仍由消费侧拒绝（custom hash 错误）。
func TestAsymInsecureGate_SM2RejectedWithGate(t *testing.T) {
	_, err := rootcrypto.NewAsymmetric(rootcrypto.SM2,
		rootcrypto.WithAsymHash(crypto.SHA1),
		rootcrypto.WithAsymInsecureAlgorithms(),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not support custom asymmetric hash")
}

// TestAsymInsecureGate_EncryptUnaffected padding/hash 切换不污染加密路径：
// v1.5+SHA-1 全 opt-in 实例 Encrypt/Decrypt 仍走 OAEP，往返成功，
// 且密文可被标准库 rsa.DecryptOAEP(SHA-1) 解开（佐证格式为 OAEP）。
func TestAsymInsecureGate_EncryptUnaffected(t *testing.T) {
	prv := gateTestRSAKey(t)
	s, err := rootcrypto.NewAsymmetric(rootcrypto.RSA, append(v15SHA1Opts(),
		rootcrypto.WithPrivateKeyObject(prv))...)
	require.NoError(t, err)

	plaintext := []byte("encryption path stays OAEP")
	ct, err := s.Encrypt(plaintext)
	require.NoError(t, err)
	pt, err := s.Decrypt([]byte(ct))
	require.NoError(t, err)
	assert.Equal(t, string(plaintext), string(pt))

	stdPT, err := rsa.DecryptOAEP(crypto.SHA1.New(), rand.Reader, prv, []byte(ct), []byte{})
	assert.NoError(t, err, "密文应可被标准库 OAEP(SHA-1) 解开，证明加密未被 v1.5 污染")
	assert.Equal(t, plaintext, stdPT)
}

// TestAsymInsecureGate_MD5StillApplyReject 回归：MD5 等其余非法摘要仍在应用期
// 返回 ErrInvalidAsymOption（不因 SHA-1 放行而扩大白名单）。
func TestAsymInsecureGate_MD5StillApplyReject(t *testing.T) {
	cfg := &rootcrypto.AsymConfig{}
	err := apply(cfg, rootcrypto.WithAsymHash(crypto.MD5))
	assert.ErrorIs(t, err, rootcrypto.ErrInvalidAsymOption)
	assert.Zero(t, cfg.Hash)

	_, err = rootcrypto.NewAsymmetric(rootcrypto.RSA, rootcrypto.WithAsymHash(crypto.MD5))
	assert.ErrorIs(t, err, rootcrypto.ErrInvalidAsymOption, "构造入口对 MD5 仍应用期拒绝")
}

// TestAsymInsecureGate_ED25519Unaffected 边界完整性：ED25519 不读 Hash 与
// 闸门字段，带 SHA-1 选项 + 闸门构造仍成功且往返正常（锁定新闸门不波及
// ED25519 引擎）。
func TestAsymInsecureGate_ED25519Unaffected(t *testing.T) {
	a, err := rootcrypto.NewAsymmetric(rootcrypto.ED25519,
		rootcrypto.WithAsymHash(crypto.SHA1),
		rootcrypto.WithAsymInsecureAlgorithms())
	require.NoError(t, err)
	kp, err := a.GenerateKey()
	require.NoError(t, err)
	require.NotNil(t, kp)
	msg := []byte("ed25519 unaffected by asymmetric gate")
	sig, err := a.Sign(msg)
	require.NoError(t, err)
	assert.True(t, a.Verify(msg, sig))
}
