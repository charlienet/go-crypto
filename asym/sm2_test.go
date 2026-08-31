package asym_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"testing"

	rootcrypto "github.com/charlienet/go-crypto"
	"github.com/emmansun/gmsm/sm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSM2EncryptDecrypt：固定密钥构造 → GenerateKey → Encrypt/Decrypt 往返。
func TestSM2EncryptDecrypt(t *testing.T) {
	// test-only：固定测试密钥，仅用于本测试，不得用于生产
	prv := `MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQg7nHbhssWUlVg0Q0z9cYSL00bYdgl7RPhVfKqln7b8j+gCgYIKoEcz1UBgi2hRANCAATLAFa0PaGJuCdAN8iHlPhGWwheohe4SINFlZOmEe2MUxHrlutXyhnPOOLsUt3G9r8wxHDXYt8c5tUUzMQ5aAci`
	pub := `MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEywBWtD2hibgnQDfIh5T4RlsIXqIXuEiDRZWTphHtjFMR65brV8oZzzji7FLdxva/MMRw12LfHObVFMzEOWgHIg==`

	s, err := rootcrypto.NewAsymmetric(rootcrypto.SM2, rootcrypto.WithPrivateKey(prv), rootcrypto.WithPublicKey(pub))
	assert.NoError(t, err)

	keyPart, err := s.GenerateKey()
	assert.NoError(t, err)
	// 仅打印密钥类型，避免测试日志泄露密钥明文
	t.Logf("generated private key type: %T", keyPart.PrivateKey)
	t.Logf("generated public key type: %T", keyPart.PublicKey)

	encrypted, err := s.Encrypt([]byte("hello world"))
	assert.NoError(t, err)
	t.Logf("encrypted length: %d bytes", len(encrypted))

	decrypted, err := s.Decrypt(encrypted)
	assert.NoError(t, err)
	assert.Equal(t, "hello world", string(decrypted))
	t.Log("decrypt ok")
}

// TestSM2LegacyDERCompatibility：存量 tjfoc/gmsm DER 样本向后兼容验证。
//
// 以下样本均来自 tjfoc/gmsm v1.4.1 生成的 PKCS#8/SPKI DER 数据。
// 验证 emmansun/gmsm v0.44.1 可正确解析、加解密、签名。
func TestSM2LegacyDERCompatibility(t *testing.T) {
	// tjfoc/gmsm 生成的 PKCS#8 私钥 DER（base64）
	legacyPrivDER := `MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgYdEfj4uNxi5U4WOlRC3/K8BLQBEAv/jrYJ50RMX29XqgCgYIKoEcz1UBgi2hRANCAASnEzPWL4n/XDWcEjqHC9kbTAE0Xw1NIidI4r0kN8SQDfpb3ZT0rpYypdlyryNt/Of5DJe01+03lArAtpXlZn1/`

	// tjfoc/gmsm 生成的 SPKI 公钥 DER（base64）
	legacyPubDER := `MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEpxMz1i+J/1w1nBI6hwvZG0wBNF8NTSInSOK9JDfEkA36W92U9K6WMqXZcq8jbfzn+QyXtNftN5QKwLaV5WZ9fw==`

	// tjfoc 加密的存量密文（ASN.1，明文 "legacy sample plaintext"）
	legacyCiphertext := `MIGBAiEAhzoWH9Aq0/AH5UihbwlGu5lSijhRU+FC4oK55zc/pMwCIQCum529pjcB3CX1fQN4bUBK6mMttfImPVA1+7uN5//RDAQgr0X3LfVUyIpE0VqaR3jwPWQ/tbKZkSY/f/rYXvsqLNYEF3k0zVuqL8E+Pd0Agg4VQ0d32GVn8vdb`

	t.Run("NewAsymmetric_with_legacy_keys", func(t *testing.T) {
		s, err := rootcrypto.NewAsymmetric(rootcrypto.SM2, rootcrypto.WithPrivateKey(legacyPrivDER), rootcrypto.WithPublicKey(legacyPubDER))
		assert.NoError(t, err)
		assert.Equal(t, "SM2", s.Name())
	})

	t.Run("EncryptDecrypt_roundtrip", func(t *testing.T) {
		s, err := rootcrypto.NewAsymmetric(rootcrypto.SM2, rootcrypto.WithPrivateKey(legacyPrivDER), rootcrypto.WithPublicKey(legacyPubDER))
		assert.NoError(t, err)

		encrypted, err := s.Encrypt([]byte("test legacy key"))
		assert.NoError(t, err)
		assert.NotEmpty(t, encrypted)

		decrypted, err := s.Decrypt(encrypted)
		assert.NoError(t, err)
		assert.Equal(t, "test legacy key", string(decrypted))
	})

	t.Run("Decrypt_legacy_ciphertext", func(t *testing.T) {
		s, err := rootcrypto.NewAsymmetric(rootcrypto.SM2, rootcrypto.WithPrivateKey(legacyPrivDER), rootcrypto.WithPublicKey(legacyPubDER))
		assert.NoError(t, err)

		cipherBytes, err := base64.StdEncoding.DecodeString(legacyCiphertext)
		assert.NoError(t, err)

		decrypted, err := s.Decrypt(cipherBytes)
		assert.NoError(t, err)
		assert.Equal(t, "legacy sample plaintext", string(decrypted))
	})

	t.Run("SignVerify_roundtrip", func(t *testing.T) {
		s, err := rootcrypto.NewAsymmetric(rootcrypto.SM2, rootcrypto.WithPrivateKey(legacyPrivDER), rootcrypto.WithPublicKey(legacyPubDER))
		assert.NoError(t, err)

		msg := []byte("msg")
		sig, err := s.Sign(msg)
		assert.NoError(t, err)
		assert.True(t, s.Verify(msg, sig))
	})
}

// ==================== SM2 ExportPublicKey ====================

func TestSM2_ExportPublicKey(t *testing.T) {
	s, err := rootcrypto.NewAsymmetric(rootcrypto.SM2)
	assert.NoError(t, err)

	kp, err := s.GenerateKey()
	assert.NoError(t, err)
	assert.NotEmpty(t, kp.PrivateKey)

	// 仅设置私钥
	signer, err := rootcrypto.NewAsymmetric(rootcrypto.SM2, rootcrypto.WithPrivateKeyObject(kp.PrivateKey))
	assert.NoError(t, err)

	pubB64, err := signer.ExportPublicKey()
	assert.NoError(t, err)
	assert.NotEmpty(t, pubB64)

	// 用导出的公钥回读并验证签名
	verifier, err := rootcrypto.NewAsymmetric(rootcrypto.SM2, rootcrypto.WithPublicKey(pubB64))
	assert.NoError(t, err)

	msg := []byte("test export roundtrip")
	sig, err := signer.Sign(msg)
	assert.NoError(t, err)
	assert.True(t, verifier.Verify(msg, sig))
}

// ==================== SM2 nil key paths ====================

func TestSM2_NilKeyPaths(t *testing.T) {
	s, err := rootcrypto.NewAsymmetric(rootcrypto.SM2)
	assert.NoError(t, err)

	_, err = s.Encrypt([]byte("test"))
	assert.Error(t, err)

	_, err = s.Decrypt([]byte("test"))
	assert.Error(t, err)

	_, err = s.Sign([]byte("test"))
	assert.Error(t, err)

	assert.False(t, s.Verify([]byte("test"), []byte("sig")))
}

// ==================== SM2 WithPrivateKey 无效 base64 ====================

func TestSM2_WithPrivateKey_InvalidBase64(t *testing.T) {
	_, err := rootcrypto.NewAsymmetric(rootcrypto.SM2, rootcrypto.WithPrivateKey("!!!not-base64!!!"))
	assert.Error(t, err)
}

// ==================== SM2 WithPublicKey 无效 base64 ====================

func TestSM2_WithPublicKey_InvalidBase64(t *testing.T) {
	_, err := rootcrypto.NewAsymmetric(rootcrypto.SM2, rootcrypto.WithPublicKey("!!!not-base64!!!"))
	assert.Error(t, err)
}

// ==================== SM2 WithPrivateKey 非 SM2 密钥 ====================

func TestSM2_WithPrivateKey_NonSM2Key(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	prkBytes, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	assert.NoError(t, err)

	_, err = rootcrypto.NewAsymmetric(rootcrypto.SM2, rootcrypto.WithPrivateKey(base64.StdEncoding.EncodeToString(prkBytes)))
	// smx509 解析后类型断言失败或直接解析失败
	assert.Error(t, err)
}

// ==================== SM2 WithPublicKey 非 SM2 密钥 ====================

func TestSM2_WithPublicKey_NonSM2Key(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	pubBytes, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	assert.NoError(t, err)

	_, err = rootcrypto.NewAsymmetric(rootcrypto.SM2, rootcrypto.WithPublicKey(base64.StdEncoding.EncodeToString(pubBytes)))
	// smx509 解析后类型断言失败或直接解析失败
	assert.Error(t, err)
}

// ==================== SM2 空明文行为（P1 修复） ====================

func TestSM2_Encrypt_EmptyPlaintext(t *testing.T) {
	s, err := rootcrypto.NewAsymmetric(rootcrypto.SM2)
	require.NoError(t, err)

	kp, err := s.GenerateKey()
	require.NoError(t, err)
	assert.NotEmpty(t, kp.PublicKey)

	// 空明文必须返回明确错误且不 panic（gmsm 底层返回 (nil, nil)，
	// 本方法前置拒绝，避免调用方无法区分"成功空结果"与"失败"）。
	require.NotPanics(t, func() {
		encrypted, err := s.Encrypt([]byte{})
		assert.Error(t, err, "空明文必须返回错误")
		assert.Nil(t, encrypted, "空明文不应产出密文")
		assert.Contains(t, err.Error(), "empty plaintext")
	})

	// 非空明文不受影响（回归）
	encrypted, err := s.Encrypt([]byte("non-empty"))
	assert.NoError(t, err)
	assert.NotEmpty(t, encrypted)
}

// ==================== SM2 WithPublicKey 拒绝普通 P256 公钥（P1 C4） ====================

func TestSM2_WithPublicKey_NonSM2Curve(t *testing.T) {
	// 普通 NIST P256 公钥：曲线不属于 SM2，字符串路径必须拒绝
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pubBytes, err := x509.MarshalPKIXPublicKey(&ecdsaKey.PublicKey)
	require.NoError(t, err)

	_, err = rootcrypto.NewAsymmetric(rootcrypto.SM2, rootcrypto.WithPublicKey(base64.StdEncoding.EncodeToString(pubBytes)))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not an SM2 public key")
}

// ==================== SM2 加解密（自根包 crypto_test.go 迁入） ====================

func TestSM2_SignAndVerify(t *testing.T) {
	// 生成密钥对
	sm2Algo, err := rootcrypto.NewAsymmetric(rootcrypto.SM2)
	assert.NoError(t, err)

	keyPair, err := sm2Algo.GenerateKey()
	assert.NoError(t, err)
	assert.NotEmpty(t, keyPair.PrivateKey)
	assert.NotEmpty(t, keyPair.PublicKey)

	// 创建新实例设置私钥用于签名
	signer, err := rootcrypto.NewAsymmetric(rootcrypto.SM2, rootcrypto.WithPrivateKeyObject(keyPair.PrivateKey))
	assert.NoError(t, err)

	// 签名
	message := []byte("test message")
	signature, err := signer.Sign(message)
	assert.NoError(t, err)
	assert.NotEmpty(t, signature)

	// 创建新实例设置公钥用于验证
	verifier, err := rootcrypto.NewAsymmetric(rootcrypto.SM2, rootcrypto.WithPublicKeyObject(keyPair.PublicKey))
	assert.NoError(t, err)

	// 验证
	valid := verifier.Verify(message, signature)
	assert.True(t, valid)
}

func TestSM2_EncryptAndDecrypt(t *testing.T) {
	// 生成密钥对
	sm2Algo, err := rootcrypto.NewAsymmetric(rootcrypto.SM2)
	assert.NoError(t, err)

	keyPair, err := sm2Algo.GenerateKey()
	assert.NoError(t, err)

	// 创建新实例设置密钥
	algo, err := rootcrypto.NewAsymmetric(rootcrypto.SM2, rootcrypto.WithPrivateKeyObject(keyPair.PrivateKey), rootcrypto.WithPublicKeyObject(keyPair.PublicKey))
	assert.NoError(t, err)

	// 加密
	plaintext := []byte("secret message")
	ciphertext, err := algo.Encrypt(plaintext)
	assert.NoError(t, err)
	assert.NotEqual(t, plaintext, []byte(ciphertext))

	// 解密
	decrypted, err := algo.Decrypt(ciphertext)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, []byte(decrypted))
}

// ==================== SM2 UID 接线（P3#26b） ====================

// TestSM2_DefaultUID_SignVerify_Interop 默认 UID 签验往返，且与 gmsm
// 直接调用字节级互操作：替换 Sign/Verify 实现（弃用 API → NewSM2SignerOption
// / VerifyASN1WithSM2 显式 UID）前后，默认 UID 路径行为完全一致。
func TestSM2_DefaultUID_SignVerify_Interop(t *testing.T) {
	s, err := rootcrypto.NewAsymmetric(rootcrypto.SM2)
	require.NoError(t, err)

	kp, err := s.GenerateKey()
	require.NoError(t, err)
	sm2Prk, ok := kp.PrivateKey.(*sm2.PrivateKey)
	require.True(t, ok)

	msg := []byte("default uid interop")

	sig, err := s.Sign(msg)
	require.NoError(t, err)
	assert.True(t, s.Verify(msg, sig), "默认 UID 同实例签验应通过")

	// 本库签名可被 gmsm 直接调用（默认 UID）验证——证明字节符合 gmsm 规范
	assert.True(t, sm2.VerifyASN1WithSM2(&sm2Prk.PublicKey, nil, msg, sig),
		"gmsm 直接 VerifyASN1WithSM2 应接受本库签名")

	// gmsm deprecated SignWithSM2（默认 UID）签名可被本库 Verify 接受
	gmsmSig, err := sm2Prk.SignWithSM2(rand.Reader, nil, msg)
	require.NoError(t, err)
	assert.True(t, s.Verify(msg, gmsmSig), "本库 Verify 应接受 gmsm 直接签名")
}

// TestSM2_CustomUID_Mismatch 自定义 UID 语义：Sign 侧与 Verify 侧 UID 必须
// 同源——自定义 UID 签名交给默认 UID 验签必须失败；两侧同用自定义 UID
// 则通过。
func TestSM2_CustomUID_Mismatch(t *testing.T) {
	customUID := []byte("custom-uid-12345")

	gen, err := rootcrypto.NewAsymmetric(rootcrypto.SM2)
	require.NoError(t, err)
	kp, err := gen.GenerateKey()
	require.NoError(t, err)

	signer, err := rootcrypto.NewAsymmetric(rootcrypto.SM2,
		rootcrypto.WithPrivateKeyObject(kp.PrivateKey),
		rootcrypto.WithSM2UID(customUID))
	require.NoError(t, err)

	verifierDefault, err := rootcrypto.NewAsymmetric(rootcrypto.SM2,
		rootcrypto.WithPublicKeyObject(kp.PublicKey))
	require.NoError(t, err)

	verifierCustom, err := rootcrypto.NewAsymmetric(rootcrypto.SM2,
		rootcrypto.WithPublicKeyObject(kp.PublicKey),
		rootcrypto.WithSM2UID(customUID))
	require.NoError(t, err)

	msg := []byte("custom uid mismatch test")
	sig, err := signer.Sign(msg)
	require.NoError(t, err)

	assert.False(t, verifierDefault.Verify(msg, sig),
		"自定义 UID 签名不应被默认 UID 验签接受")
	assert.True(t, verifierCustom.Verify(msg, sig),
		"相同自定义 UID 验签应通过")
	assert.True(t, signer.Verify(msg, sig),
		"Sign/Verify 同实例同 UID 应通过")
}

// ==================== SM2 自定义哈希拒绝（P3#24） ====================

// TestSM2_CustomAsymHash_Rejected SM2 固定使用 SM3 摘要，不支持自定义
// 签名摘要算法：显式传 WithAsymHash（根包白名单已放行）后消费侧显式报错。
func TestSM2_CustomAsymHash_Rejected(t *testing.T) {
	_, err := rootcrypto.NewAsymmetric(rootcrypto.SM2, rootcrypto.WithAsymHash(crypto.SHA384))
	assert.Error(t, err, "SM2 不应接受自定义签名哈希")
	assert.Contains(t, err.Error(), "does not support custom asymmetric hash")

	// 默认（未设置）不受影响
	_, err = rootcrypto.NewAsymmetric(rootcrypto.SM2)
	assert.NoError(t, err)
}

// ==================== SM2 公钥 IsOnCurve 显式校验（P3#26a） ====================

// sm2oidECPublicKey / sm2oidCurve SM2 SPKI 的算法 OID 与曲线 OID
// （与 smx509 编码一致：id-ecPublicKey || SM2 曲线 OID）。
var (
	sm2oidECPublicKey = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	sm2oidCurve       = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301}
)

// sm2SPKI 手工构造用的 SPKI 结构（crypto/x509/pkix 未公开 PublicKeyInfo，
// 与标准库内部 publicKeyInfo 同构）。
type sm2SPKI struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// marshalSM2SPKI 手工构造 SM2 公钥 SPKI DER（0x04 未压缩点编码）：
// smx509.MarshalPKIXPublicKey 自校验点合法性，无法编码非法点，
// 故绕过 smx509 手工拼装，验证解析侧（withPublicKey 字符串路径）的
// IsOnCurve 显式校验。
func marshalSM2SPKI(t *testing.T, curve elliptic.Curve, x, y *big.Int) []byte {
	t.Helper()

	paramBytes, err := asn1.Marshal(sm2oidCurve)
	require.NoError(t, err)

	byteLen := (curve.Params().BitSize + 7) / 8
	point := append([]byte{0x04},
		append(x.FillBytes(make([]byte, byteLen)), y.FillBytes(make([]byte, byteLen))...)...)

	der, err := asn1.Marshal(sm2SPKI{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm:  sm2oidECPublicKey,
			Parameters: asn1.RawValue{FullBytes: paramBytes},
		},
		PublicKey: asn1.BitString{Bytes: point, BitLength: len(point) * 8},
	})
	require.NoError(t, err)
	return der
}

// TestSM2_InvalidPointOnCurve_Rejected (1,1) 坐标合法但不在 SM2 曲线上：
// 三条注入路径（私钥对象转换/公钥对象/公钥字符串）都必须拒绝。
func TestSM2_InvalidPointOnCurve_Rejected(t *testing.T) {
	// SM2 曲线上的非法点：曲线为 sm2.P256() 单例（IsSM2PublicKey 曲线身份
	// 检查可通过），但 (1,1) 不满足曲线方程 → IsOnCurve 必须为 false。
	invalid := &ecdsa.PublicKey{Curve: sm2.P256(), X: big.NewInt(1), Y: big.NewInt(1)}
	require.False(t, invalid.IsOnCurve(invalid.X, invalid.Y),
		"测试前置失败：(1,1) 应不在 SM2 曲线上")

	// 公钥对象注入路径：拒绝
	_, err := rootcrypto.NewAsymmetric(rootcrypto.SM2, rootcrypto.WithPublicKeyObject(invalid))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not on curve")

	// 私钥对象注入路径（ecdsa.PrivateKey → sm2 转换分支）：拒绝
	invalidPrk := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: sm2.P256(), X: big.NewInt(1), Y: big.NewInt(1)},
		D:         big.NewInt(1),
	}
	_, err = rootcrypto.NewAsymmetric(rootcrypto.SM2, rootcrypto.WithPrivateKeyObject(invalidPrk))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not on curve")

	// 字符串注入路径：手工构造非法点 SPKI DER。
	// 注意：smx509.ParsePKIXPublicKey 解析点在先（"failed to unmarshal
	// elliptic curve point"），sm2_algo.WithPublicKey 的 IsOnCurve 检查是
	// 解析层之后的纵深防御——此处断言注入被拒绝即可，不断言具体消息
	//（错误可能来自解析层而非本包校验）。
	der := marshalSM2SPKI(t, sm2.P256(), big.NewInt(1), big.NewInt(1))
	_, err = rootcrypto.NewAsymmetric(rootcrypto.SM2,
		rootcrypto.WithPublicKey(base64.StdEncoding.EncodeToString(der)))
	assert.Error(t, err)

	// 回归：marshalSM2SPKI 对合法曲线点的编码可被 smx509 解析并接受
	// （证明手工构造的 DER 结构与 smx509 视角一致，非法点拒绝源于
	// IsOnCurve 校验而非格式错误）。
	gen, err := rootcrypto.NewAsymmetric(rootcrypto.SM2)
	require.NoError(t, err)
	kp, err := gen.GenerateKey()
	require.NoError(t, err)
	sm2Pub, ok := kp.PublicKey.(*ecdsa.PublicKey)
	require.True(t, ok)
	validDer := marshalSM2SPKI(t, sm2Pub.Curve, sm2Pub.X, sm2Pub.Y)
	validAlgo, err := rootcrypto.NewAsymmetric(rootcrypto.SM2,
		rootcrypto.WithPublicKey(base64.StdEncoding.EncodeToString(validDer)))
	require.NoError(t, err, "合法 SM2 点的手工 DER 应被接受")
	msg := []byte("valid manual spki")
	validSig, err := gen.Sign(msg)
	require.NoError(t, err)
	assert.True(t, validAlgo.Verify(msg, validSig), "合法手工 SPKI 注入的实例应可验签")
}

// ==================== SM2 遗留密文格式（P3#26c） ====================

// TestSM2_LegacyCipherC1C2C3 遗留模式（WithSM2LegacyCiphertext）加解密
// 往返：密文为 C1C2C3 裸拼接（首字节 0x04，非 ASN.1），且与默认模式
// （ASN.1 + C1C3C2）互解必须失败（格式隔离）。
func TestSM2_LegacyCipherC1C2C3(t *testing.T) {
	gen, err := rootcrypto.NewAsymmetric(rootcrypto.SM2)
	require.NoError(t, err)
	kp, err := gen.GenerateKey()
	require.NoError(t, err)

	legacy, err := rootcrypto.NewAsymmetric(rootcrypto.SM2,
		rootcrypto.WithPrivateKeyObject(kp.PrivateKey),
		rootcrypto.WithPublicKeyObject(kp.PublicKey),
		rootcrypto.WithSM2LegacyCiphertext())
	require.NoError(t, err)

	normal, err := rootcrypto.NewAsymmetric(rootcrypto.SM2,
		rootcrypto.WithPrivateKeyObject(kp.PrivateKey),
		rootcrypto.WithPublicKeyObject(kp.PublicKey))
	require.NoError(t, err)

	msg := []byte("sm2 legacy ciphertext roundtrip")

	// legacy 加解密往返 + 首字节 0x04（MarshalUncompressed 未压缩点前缀，非 ASN.1）
	legacyCT, err := legacy.Encrypt(msg)
	require.NoError(t, err)
	assert.Equal(t, byte(0x04), []byte(legacyCT)[0], "legacy 密文首字节应为未压缩点前缀 0x04")
	pt, err := legacy.Decrypt(legacyCT)
	require.NoError(t, err)
	assert.Equal(t, msg, []byte(pt), "legacy 模式加解密应往返")

	// 默认（新认证格式）加解密往返 + 首字节 0x30（ASN.1 SEQUENCE）
	normalCT, err := normal.Encrypt(msg)
	require.NoError(t, err)
	assert.Equal(t, byte(0x30), []byte(normalCT)[0], "默认密文首字节应为 ASN.1 SEQUENCE 0x30")
	pt2, err := normal.Decrypt(normalCT)
	require.NoError(t, err)
	assert.Equal(t, msg, []byte(pt2), "默认模式加解密应往返")

	// 互解必须失败：默认模式解 legacy 密文（拼接序/认证不匹配）
	_, err = normal.Decrypt(legacyCT)
	assert.Error(t, err, "默认模式不应能解开 legacy 密文")
	// legacy 模式解默认密文（显式拒绝 ASN.1 格式）
	_, err = legacy.Decrypt(normalCT)
	assert.Error(t, err, "legacy 模式不应能解开默认（ASN.1）密文")
}

// ==================== SM2 私钥字符串注入公钥回填（P3#20） ====================

// TestSM2_WithPrivateKeyString_BackfillsPublicKey 仅 WithPrivateKey(string)
// 注入私钥后，同实例可直接 Sign→Verify（公钥能力自动派生，
// 修复前在 Verify 时因 puk==nil 恒为 false）。
func TestSM2_WithPrivateKeyString_BackfillsPublicKey(t *testing.T) {
	// 复用固定测试密钥（TestSM2EncryptDecrypt 同源）
	prv := `MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQg7nHbhssWUlVg0Q0z9cYSL00bYdgl7RPhVfKqln7b8j+gCgYIKoEcz1UBgi2hRANCAATLAFa0PaGJuCdAN8iHlPhGWwheohe4SINFlZOmEe2MUxHrlutXyhnPOOLsUt3G9r8wxHDXYt8c5tUUzMQ5aAci`

	s, err := rootcrypto.NewAsymmetric(rootcrypto.SM2, rootcrypto.WithPrivateKey(prv))
	require.NoError(t, err)

	msg := []byte("string private key backfills public key")
	sig, err := s.Sign(msg)
	require.NoError(t, err)
	assert.True(t, s.Verify(msg, sig), "WithPrivateKey(string) 后同实例验签应通过（公钥自动派生）")
}
