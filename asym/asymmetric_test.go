package asym_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"math/big"
	"testing"

	rootcrypto "github.com/charlienet/go-crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 本文件测试经根包协议入口 crypto.NewAsymmetric 分发（asym 包 init 已在
// 测试二进制中注册四类引擎）。断言文本与迁移前完全一致。

func TestECDSA_SignAndVerify(t *testing.T) {
	algo, err := rootcrypto.NewAsymmetric(rootcrypto.ECDSA)
	require.NoError(t, err)

	kp, err := algo.GenerateKey()
	require.NoError(t, err)

	signer, err := rootcrypto.NewAsymmetric(rootcrypto.ECDSA, rootcrypto.WithPrivateKeyObject(kp.PrivateKey))
	require.NoError(t, err)

	verifier, err := rootcrypto.NewAsymmetric(rootcrypto.ECDSA, rootcrypto.WithPublicKeyObject(kp.PublicKey))
	require.NoError(t, err)

	data := []byte("hello world")
	sig, err := signer.Sign(data)
	require.NoError(t, err)

	assert.True(t, verifier.Verify(data, sig))
	assert.False(t, verifier.Verify([]byte("tampered"), sig))
}

func TestEd25519_SignAndVerify(t *testing.T) {
	algo, err := rootcrypto.NewAsymmetric(rootcrypto.ED25519)
	require.NoError(t, err)

	kp, err := algo.GenerateKey()
	require.NoError(t, err)

	signer, err := rootcrypto.NewAsymmetric(rootcrypto.ED25519, rootcrypto.WithPrivateKeyObject(kp.PrivateKey))
	require.NoError(t, err)

	verifier, err := rootcrypto.NewAsymmetric(rootcrypto.ED25519, rootcrypto.WithPublicKeyObject(kp.PublicKey))
	require.NoError(t, err)

	data := []byte("hello world")
	sig, err := signer.Sign(data)
	require.NoError(t, err)

	assert.True(t, verifier.Verify(data, sig))
	assert.False(t, verifier.Verify([]byte("tampered"), sig))
}

func TestECDSA_EncryptNotSupported(t *testing.T) {
	algo, _ := rootcrypto.NewAsymmetric(rootcrypto.ECDSA)
	_, err := algo.Encrypt([]byte("test"))
	assert.Error(t, err)
}

func TestEd25519_EncryptNotSupported(t *testing.T) {
	algo, _ := rootcrypto.NewAsymmetric(rootcrypto.ED25519)
	_, err := algo.Encrypt([]byte("test"))
	assert.Error(t, err)
}

func TestECDSA_DecryptNotSupported(t *testing.T) {
	algo, _ := rootcrypto.NewAsymmetric(rootcrypto.ECDSA)
	_, err := algo.Decrypt([]byte("test"))
	assert.Error(t, err)
}

func TestEd25519_DecryptNotSupported(t *testing.T) {
	algo, _ := rootcrypto.NewAsymmetric(rootcrypto.ED25519)
	_, err := algo.Decrypt([]byte("test"))
	assert.Error(t, err)
}

func TestECDSA_Name(t *testing.T) {
	algo, _ := rootcrypto.NewAsymmetric(rootcrypto.ECDSA)
	assert.Equal(t, "ECDSA", algo.Name())
}

func TestEd25519_Name(t *testing.T) {
	algo, _ := rootcrypto.NewAsymmetric(rootcrypto.ED25519)
	assert.Equal(t, "Ed25519", algo.Name())
}

func TestECDSA_ExportPublicKey(t *testing.T) {
	algo, err := rootcrypto.NewAsymmetric(rootcrypto.ECDSA)
	require.NoError(t, err)

	kp, err := algo.GenerateKey()
	require.NoError(t, err)

	signer, err := rootcrypto.NewAsymmetric(rootcrypto.ECDSA, rootcrypto.WithPrivateKeyObject(kp.PrivateKey))
	require.NoError(t, err)

	publicKeyStr, err := signer.ExportPublicKey()
	require.NoError(t, err)
	assert.NotEmpty(t, publicKeyStr)
}

func TestEd25519_ExportPublicKey(t *testing.T) {
	algo, err := rootcrypto.NewAsymmetric(rootcrypto.ED25519)
	require.NoError(t, err)

	kp, err := algo.GenerateKey()
	require.NoError(t, err)

	signer, err := rootcrypto.NewAsymmetric(rootcrypto.ED25519, rootcrypto.WithPrivateKeyObject(kp.PrivateKey))
	require.NoError(t, err)

	publicKeyStr, err := signer.ExportPublicKey()
	require.NoError(t, err)
	assert.NotEmpty(t, publicKeyStr)
}

// ==================== ECDSA 公钥合法性 / Ed25519 私钥长度（P1 B4/B5） ====================

func TestECDSA_InvalidPublicKeyRejected(t *testing.T) {
	// 构造不在 P256 曲线上的点（X=0, Y=0）
	invalid := &ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(0), Y: big.NewInt(0)}

	_, err := rootcrypto.NewAsymmetric(rootcrypto.ECDSA, rootcrypto.WithPublicKeyObject(invalid))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not on curve")
}

func TestECDSA_UnsupportedCurveRejected(t *testing.T) {
	// P224 曲线公钥应被拒绝（白名单仅 P-256/P-384/P-521）
	p224Key, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err)

	_, err = rootcrypto.NewAsymmetric(rootcrypto.ECDSA, rootcrypto.WithPublicKeyObject(&p224Key.PublicKey))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported ECDSA curve")
}

func TestEd25519_InvalidPrivateKeyLength(t *testing.T) {
	// 32 字节 Ed25519 私钥长度非法：构造必须返回 error，而非延迟到 Sign 才 panic
	shortKey := ed25519.PrivateKey(make([]byte, 32))

	require.NotPanics(t, func() {
		_, err := rootcrypto.NewAsymmetric(rootcrypto.ED25519, rootcrypto.WithPrivateKeyObject(shortKey))
		_ = err
	})
	_, err := rootcrypto.NewAsymmetric(rootcrypto.ED25519, rootcrypto.WithPrivateKeyObject(shortKey))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid Ed25519 private key length")
}

func TestEd25519_InvalidPublicKeyLength(t *testing.T) {
	// 非法长度公钥注入（如 16/64 字节）：构造必须返回 error，
	// 防止外部输入触发标准库 ed25519.Verify 的 panic（P1 修复）。
	for _, n := range []int{0, 16, 64} {
		badPub := ed25519.PublicKey(make([]byte, n))

		require.NotPanics(t, func() {
			_, err := rootcrypto.NewAsymmetric(rootcrypto.ED25519, rootcrypto.WithPublicKeyObject(badPub))
			_ = err
		})
		_, err := rootcrypto.NewAsymmetric(rootcrypto.ED25519, rootcrypto.WithPublicKeyObject(badPub))
		assert.Error(t, err, "长度 %d 的公钥应被拒绝", n)
		assert.Contains(t, err.Error(), "invalid Ed25519 public key length")
	}

	// 合法 32 字节公钥不受影响（回归）
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	_, err = rootcrypto.NewAsymmetric(rootcrypto.ED25519, rootcrypto.WithPublicKeyObject(pub))
	assert.NoError(t, err)
}

// ==================== ECDSA 验签 ASN.1 严格解析（P2） ====================

func TestECDSA_Verify_RejectsTrailingBytes(t *testing.T) {
	algo, err := rootcrypto.NewAsymmetric(rootcrypto.ECDSA)
	require.NoError(t, err)

	kp, err := algo.GenerateKey()
	require.NoError(t, err)

	signer, err := rootcrypto.NewAsymmetric(rootcrypto.ECDSA, rootcrypto.WithPrivateKeyObject(kp.PrivateKey))
	require.NoError(t, err)
	verifier, err := rootcrypto.NewAsymmetric(rootcrypto.ECDSA, rootcrypto.WithPublicKeyObject(kp.PublicKey))
	require.NoError(t, err)

	data := []byte("strict asn1 verification")

	// 合法签名必须验证通过（回归）
	sig, err := signer.Sign(data)
	require.NoError(t, err)
	assert.True(t, verifier.Verify(data, sig))

	// 签名后追加垃圾字节：VerifyASN1 严格完整消费 DER，必须拒绝
	appended := append(append([]byte(nil), sig...), 0x00)
	assert.False(t, verifier.Verify(data, appended), "签名后追加垃圾字节不应验签通过")

	appendedMore := append(append([]byte(nil), sig...), []byte("junk")...)
	assert.False(t, verifier.Verify(data, appendedMore), "签名后追加多字节垃圾不应验签通过")

	// 篡改签名内容仍应拒绝
	tampered := append([]byte(nil), sig...)
	tampered[len(tampered)-1] ^= 0x01
	assert.False(t, verifier.Verify(data, tampered))
}

// ==================== Ed25519 注入密钥拷贝（P3） ====================

func TestEd25519_WithPrivateKeyObject_CopiesSlice(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// 保存原始私钥副本作为期望签名基准
	privCopy := append(ed25519.PrivateKey(nil), priv...)

	signer, err := rootcrypto.NewAsymmetric(rootcrypto.ED25519, rootcrypto.WithPrivateKeyObject(priv))
	require.NoError(t, err)
	verifier, err := rootcrypto.NewAsymmetric(rootcrypto.ED25519, rootcrypto.WithPublicKeyObject(pub))
	require.NoError(t, err)

	msg := []byte("slice mutation test")
	sigBefore, err := signer.Sign(msg)
	require.NoError(t, err)

	// 篡改调用方持有的原切片：实例必须不受影响（注入时已拷贝）
	for i := range priv {
		priv[i] = 0
	}

	sigAfter, err := signer.Sign(msg)
	require.NoError(t, err)
	assert.Equal(t, sigBefore, sigAfter, "调用方修改原切片后签名应保持不变")

	// 签名仍能被原始公钥验证（证明使用的是注入时的原始密钥）
	assert.True(t, verifier.Verify(msg, sigAfter))

	// 与原始副本构造的独立实例签名一致
	refSigner, err := rootcrypto.NewAsymmetric(rootcrypto.ED25519, rootcrypto.WithPrivateKeyObject(privCopy))
	require.NoError(t, err)
	refSig, err := refSigner.Sign(msg)
	require.NoError(t, err)
	assert.Equal(t, sigBefore, refSig)
}

// ==================== ECDSA 私钥注入曲线白名单（复核修复） ====================

func TestECDSA_WithPrivateKeyObject_P224Rejected(t *testing.T) {
	// P224 私钥注入必须被拒绝（与公钥注入路径、移除 P224 意图一致）
	p224Key, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err)

	_, err = rootcrypto.NewAsymmetric(rootcrypto.ECDSA, rootcrypto.WithPrivateKeyObject(p224Key))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported ECDSA curve")

	// P256 私钥注入正常（回归）
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	s, err := rootcrypto.NewAsymmetric(rootcrypto.ECDSA, rootcrypto.WithPrivateKeyObject(p256Key))
	require.NoError(t, err)

	msg := []byte("p256 private key injection")
	sig, err := s.Sign(msg)
	require.NoError(t, err)
	assert.NotEmpty(t, sig)
}

// ==================== 协议入口未注册/拒绝路径（自根包 crypto_test.go 迁入） ====================

func TestInvalidAlgorithm(t *testing.T) {
	// 非预定义字符串值：走注册表查询，未注册报 engine 缺失错误
	_, err := rootcrypto.NewAsymmetric(rootcrypto.AsymmetricAlgorithm("INVALID"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no engine registered for")
	assert.Contains(t, err.Error(), "github.com/charlienet/go-crypto/asym")

	// 子集外枚举：ECDH 是密钥协商算法，非对称入口直接拒绝
	//（错误不含 engine 缺失提示，锁定三分校验差异）
	_, err = rootcrypto.NewAsymmetric(rootcrypto.ECDH)
	assert.Error(t, err)
	assert.NotContains(t, err.Error(), "no engine registered")
}

// TestNewAsymmetric_CustomAlgorithm_NoEngine 自定义算法（类型转换扩展）未注册时
// 报 engine 缺失错误，错误文本提示导入对应实现包。
func TestNewAsymmetric_CustomAlgorithm_NoEngine(t *testing.T) {
	_, err := rootcrypto.NewAsymmetric(rootcrypto.AsymmetricAlgorithm("ML-KEM"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no engine registered for")
	assert.Contains(t, err.Error(), "github.com/charlienet/go-crypto/asym")
}

// ==================== ECDSA 低 S 规范化（P2-D5） ====================

// ecdsaSigASN1 与实现侧一致的 DER 签名结构（SEQUENCE { r, s INTEGER }）。
type ecdsaSigASN1 struct {
	R, S *big.Int
}

// TestECDSA_LowS_SignNormalization Sign 输出必须全部为低 S（s ≤ N/2）：
// 100 轮随机签名逐一解析断言，且每轮验签通过（规范化不破坏签名有效性）。
func TestECDSA_LowS_SignNormalization(t *testing.T) {
	algo, err := rootcrypto.NewAsymmetric(rootcrypto.ECDSA)
	require.NoError(t, err)

	kp, err := algo.GenerateKey()
	require.NoError(t, err)
	ecdsaPrk, ok := kp.PrivateKey.(*ecdsa.PrivateKey)
	require.True(t, ok)

	verifier, err := rootcrypto.NewAsymmetric(rootcrypto.ECDSA, rootcrypto.WithPublicKeyObject(kp.PublicKey))
	require.NoError(t, err)

	data := []byte("low-s normalization loop")
	halfOrder := new(big.Int).Rsh(new(big.Int).Set(ecdsaPrk.Curve.Params().N), 1)

	for i := 0; i < 100; i++ {
		sig, err := algo.Sign(data)
		require.NoError(t, err)

		var parsed ecdsaSigASN1
		_, err = asn1.Unmarshal(sig, &parsed)
		require.NoError(t, err, "第 %d 轮签名应为合法 ASN.1 DER", i)
		assert.Greater(t, parsed.S.Sign(), 0, "第 %d 轮签名 s 必须为正", i)
		assert.LessOrEqual(t, parsed.S.Cmp(halfOrder), 0, "第 %d 轮签名 s 必须 ≤ N/2（低 S）", i)

		assert.True(t, verifier.Verify(data, sig), "第 %d 轮签名应验证通过", i)
	}
}

// TestECDSA_HighS_VerifyRejected 构造高 S 签名（s' := N - s 重编码）：
// Verify 必须拒绝——防止攻击者将合法签名 (r, s) 翻转为 (r, N-s) 绕过
// 基于签名形态的黑名单/去重。
func TestECDSA_HighS_VerifyRejected(t *testing.T) {
	algo, err := rootcrypto.NewAsymmetric(rootcrypto.ECDSA)
	require.NoError(t, err)

	kp, err := algo.GenerateKey()
	require.NoError(t, err)
	ecdsaPrk, ok := kp.PrivateKey.(*ecdsa.PrivateKey)
	require.True(t, ok)

	verifier, err := rootcrypto.NewAsymmetric(rootcrypto.ECDSA, rootcrypto.WithPublicKeyObject(kp.PublicKey))
	require.NoError(t, err)

	data := []byte("high-s must be rejected")
	sig, err := algo.Sign(data)
	require.NoError(t, err)
	assert.True(t, verifier.Verify(data, sig), "低 S 合法签名应通过（回归）")

	// 取合法签名（Sign 已保证低 S），翻转为高 S 重编码
	var parsed ecdsaSigASN1
	_, err = asn1.Unmarshal(sig, &parsed)
	require.NoError(t, err)

	n := ecdsaPrk.Curve.Params().N
	halfOrder := new(big.Int).Rsh(new(big.Int).Set(n), 1)
	if parsed.S.Cmp(halfOrder) > 0 {
		t.Fatal("测试前置条件失败：Sign 产物应为低 S 签名")
	}

	highS := new(big.Int).Sub(n, parsed.S)
	assert.True(t, highS.Cmp(halfOrder) > 0, "翻转后的 s' 应大于 N/2")

	highSSig, err := asn1.Marshal(ecdsaSigASN1{R: parsed.R, S: highS})
	require.NoError(t, err)

	assert.False(t, verifier.Verify(data, highSSig), "高 S 签名必须被拒绝")

	// 篡改后的签名仍应被拒绝（低 S 检查不放松原有严格 DER 语义）
	tampered := append([]byte(nil), highSSig...)
	tampered[len(tampered)-1] ^= 0x01
	assert.False(t, verifier.Verify(data, tampered))
}

// TestECDSA_LowS_StdInterop 本库低 S 规范化签名与标准库互操作：
// 标准库 VerifyASN1 应接受本库签名（std 对高/低 S 均放行），
// 证明规范化不破坏跨实现兼容性。
func TestECDSA_LowS_StdInterop(t *testing.T) {
	algo, err := rootcrypto.NewAsymmetric(rootcrypto.ECDSA)
	require.NoError(t, err)

	kp, err := algo.GenerateKey()
	require.NoError(t, err)
	ecdsaPrk, ok := kp.PrivateKey.(*ecdsa.PrivateKey)
	require.True(t, ok)

	// 标准库签名对应 P-256 + SHA-256（本库默认）
	data := []byte("std interop after low-s normalization")
	sig, err := algo.Sign(data)
	require.NoError(t, err)

	h := crypto.SHA256.New()
	h.Write(data)
	digest := h.Sum(nil)
	assert.True(t, ecdsa.VerifyASN1(&ecdsaPrk.PublicKey, digest, sig),
		"标准库 ecdsa.VerifyASN1 应接受本库低 S 签名")
}

// ==================== ECDSA 曲线/哈希配置消费（P3#24） ====================

// TestECDSA_CurveAndHash_Consumption P-384 + SHA-384 与 P-521 配置接线：
// GenerateKey 使用配置曲线；签名/验签使用配置哈希。
func TestECDSA_CurveAndHash_Consumption(t *testing.T) {
	t.Run("P384_SHA384_roundtrip", func(t *testing.T) {
		// 根包选项层已归一存储 "P384"（大小写/连字符变体均可传入）
		algo, err := rootcrypto.NewAsymmetric(rootcrypto.ECDSA,
			rootcrypto.WithECDSACurve("P-384"),
			rootcrypto.WithAsymHash(crypto.SHA384))
		require.NoError(t, err)

		kp, err := algo.GenerateKey()
		require.NoError(t, err)
		ecdsaPrk, ok := kp.PrivateKey.(*ecdsa.PrivateKey)
		require.True(t, ok)
		assert.Equal(t, elliptic.P384(), ecdsaPrk.Curve, "GenerateKey 应使用配置的 P-384 曲线")
		assert.Equal(t, 384, ecdsaPrk.Curve.Params().BitSize)

		msg := []byte("p384 + sha384 sign verify roundtrip")

		// 同实例往返（同时覆盖 GenerateKey 公钥回填）
		sig, err := algo.Sign(msg)
		require.NoError(t, err)
		assert.True(t, algo.Verify(msg, sig), "同实例 P-384/SHA-384 验签应通过")

		// 独立 verifier（对象注入 P-384 公钥 + 同哈希配置）验签：
		// 覆盖曲线白名单对象身份比较对 P-384 的兼容（非仅 GenerateKey 自洽）
		verifier, err := rootcrypto.NewAsymmetric(rootcrypto.ECDSA,
			rootcrypto.WithPublicKeyObject(kp.PublicKey),
			rootcrypto.WithAsymHash(crypto.SHA384))
		require.NoError(t, err)
		assert.True(t, verifier.Verify(msg, sig), "独立 P-384/SHA-384 验签应通过")
	})

	t.Run("P521_default_hash", func(t *testing.T) {
		algo, err := rootcrypto.NewAsymmetric(rootcrypto.ECDSA,
			rootcrypto.WithECDSACurve("P-521"))
		require.NoError(t, err)

		kp, err := algo.GenerateKey()
		require.NoError(t, err)
		ecdsaPrk, ok := kp.PrivateKey.(*ecdsa.PrivateKey)
		require.True(t, ok)
		assert.Equal(t, elliptic.P521(), ecdsaPrk.Curve, "GenerateKey 应使用配置的 P-521 曲线")

		msg := []byte("p521 default sha256")
		sig, err := algo.Sign(msg)
		require.NoError(t, err)
		assert.True(t, algo.Verify(msg, sig))
	})

	t.Run("default_P256", func(t *testing.T) {
		algo, err := rootcrypto.NewAsymmetric(rootcrypto.ECDSA)
		require.NoError(t, err)

		kp, err := algo.GenerateKey()
		require.NoError(t, err)
		ecdsaPrk, ok := kp.PrivateKey.(*ecdsa.PrivateKey)
		require.True(t, ok)
		assert.Equal(t, elliptic.P256(), ecdsaPrk.Curve, "默认曲线应为 P-256")
	})
}

// ==================== 同实例能力补全（P3#20） ====================

// TestAsymmetric_GenerateKey_SameInstance 四算法 GenerateKey 后同一实例
// 直接 Sign→Verify / Encrypt→Decrypt（公钥能力自动派生，无需另行注入）。
func TestAsymmetric_GenerateKey_SameInstance(t *testing.T) {
	for _, alg := range []rootcrypto.AsymmetricAlgorithm{
		rootcrypto.RSA, rootcrypto.ECDSA, rootcrypto.ED25519, rootcrypto.SM2,
	} {
		t.Run(alg.String(), func(t *testing.T) {
			s, err := rootcrypto.NewAsymmetric(alg)
			require.NoError(t, err)

			kp, err := s.GenerateKey()
			require.NoError(t, err)
			require.NotNil(t, kp.PrivateKey)

			msg := []byte("same-instance after generate-key")
			sig, err := s.Sign(msg)
			require.NoError(t, err)
			assert.True(t, s.Verify(msg, sig), "%s GenerateKey 后同实例 Sign→Verify 应通过", alg)

			// RSA/SM2 支持加解密：同实例 Encrypt→Decrypt 往返
			if alg == rootcrypto.RSA || alg == rootcrypto.SM2 {
				ct, err := s.Encrypt([]byte("same-instance plaintext"))
				require.NoError(t, err)
				pt, err := s.Decrypt(ct)
				require.NoError(t, err)
				assert.Equal(t, "same-instance plaintext", string(pt), "%s 同实例 Encrypt→Decrypt 应往返", alg)
			}
		})
	}
}
