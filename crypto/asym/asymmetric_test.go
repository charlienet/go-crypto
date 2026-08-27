package asym_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"

	rootcrypto "github.com/charlienet/go-crypto/crypto"
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
	assert.Contains(t, err.Error(), "github.com/charlienet/go-crypto/crypto/asym")

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
	assert.Contains(t, err.Error(), "github.com/charlienet/go-crypto/crypto/asym")
}
