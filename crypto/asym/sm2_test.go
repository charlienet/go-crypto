package asym_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"testing"

	rootcrypto "github.com/charlienet/go-crypto/crypto"
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

// ==================== SM2 空明文行为（P3） ====================

func TestSM2_Encrypt_EmptyPlaintext(t *testing.T) {
	s, err := rootcrypto.NewAsymmetric(rootcrypto.SM2)
	require.NoError(t, err)

	kp, err := s.GenerateKey()
	require.NoError(t, err)
	assert.NotEmpty(t, kp.PublicKey)

	// gmsm 底层对空明文返回 (nil, nil)：固化当前行为——
	// 不报错、不 panic、且不产出任何密文。
	require.NotPanics(t, func() {
		encrypted, err := s.Encrypt([]byte{})
		assert.NoError(t, err)
		assert.Empty(t, encrypted, "空明文应返回空密文")
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
