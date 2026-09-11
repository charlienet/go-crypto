package envelope

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/cloudflare/circl/hpke"
	"github.com/stretchr/testify/require"
)

func TestHPKERoundTrip(t *testing.T) {
	// 生成 X25519 密钥对
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	pub := priv.PublicKey()

	// 测试数据
	plaintext := []byte("Hello, HPKE World!")
	info := []byte("test-context")

	// 加密
	enc, ciphertext, err := HPKESeal(HPKE_X25519_HKDF_SHA256_AES_256_GCM, pub, plaintext, info)
	require.NoError(t, err)
	require.NotEmpty(t, enc)
	require.NotEmpty(t, ciphertext)
	require.Len(t, enc, 32, "enc should be 32 bytes (X25519 public key)")

	// 解密
	decrypted, err := HPKEOpen(HPKE_X25519_HKDF_SHA256_AES_256_GCM, priv, enc, ciphertext, info)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)
}

func TestHPKEWithNilInfo(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	pub := priv.PublicKey()

	plaintext := []byte("test with nil info")

	// info 为 nil
	enc, ciphertext, err := HPKESeal(HPKE_X25519_HKDF_SHA256_AES_256_GCM, pub, plaintext, nil)
	require.NoError(t, err)

	decrypted, err := HPKEOpen(HPKE_X25519_HKDF_SHA256_AES_256_GCM, priv, enc, ciphertext, nil)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)
}

func TestHPKEEmptyPlaintext(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	pub := priv.PublicKey()

	plaintext := []byte{}
	info := []byte("empty plaintext test")

	enc, ciphertext, err := HPKESeal(HPKE_X25519_HKDF_SHA256_AES_256_GCM, pub, plaintext, info)
	require.NoError(t, err)

	decrypted, err := HPKEOpen(HPKE_X25519_HKDF_SHA256_AES_256_GCM, priv, enc, ciphertext, info)
	require.NoError(t, err)
	// 空明文可能返回 []byte{} 或 nil，都表示空
	require.True(t, len(decrypted) == 0, "decrypted plaintext should be empty")
}

func TestHPKELargePlaintext(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	pub := priv.PublicKey()

	// 1MB 数据
	plaintext := make([]byte, 1024*1024)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}
	info := []byte("large plaintext test")

	enc, ciphertext, err := HPKESeal(HPKE_X25519_HKDF_SHA256_AES_256_GCM, pub, plaintext, info)
	require.NoError(t, err)

	decrypted, err := HPKEOpen(HPKE_X25519_HKDF_SHA256_AES_256_GCM, priv, enc, ciphertext, info)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)
}

func TestHPKEUnsupportedSuite(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	pub := priv.PublicKey()

	plaintext := []byte("test")

	// 不支持的 suite
	invalidSuite := HPKESuite{0x9999, 0x9999, 0x9999}

	_, _, err = HPKESeal(invalidSuite, pub, plaintext, nil)
	require.ErrorIs(t, err, ErrHPKEUnsupportedSuite)

	_, err = HPKEOpen(invalidSuite, priv, []byte{}, []byte{}, nil)
	require.ErrorIs(t, err, ErrHPKEUnsupportedSuite)
}

func TestHPKEUnsupportedKey(t *testing.T) {
	// 使用 P-256 曲线（非 X25519）
	privP256, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	pubP256 := privP256.PublicKey()

	plaintext := []byte("test")

	// 加密时使用非 X25519 密钥
	_, _, err = HPKESeal(HPKE_X25519_HKDF_SHA256_AES_256_GCM, pubP256, plaintext, nil)
	require.ErrorIs(t, err, ErrHPKEUnsupportedKey)

	// 解密时使用非 X25519 密钥
	_, err = HPKEOpen(HPKE_X25519_HKDF_SHA256_AES_256_GCM, privP256, []byte{}, []byte{}, nil)
	require.ErrorIs(t, err, ErrHPKEUnsupportedKey)

	// nil 密钥
	_, _, err = HPKESeal(HPKE_X25519_HKDF_SHA256_AES_256_GCM, nil, plaintext, nil)
	require.ErrorIs(t, err, ErrHPKEUnsupportedKey)

	_, err = HPKEOpen(HPKE_X25519_HKDF_SHA256_AES_256_GCM, nil, []byte{}, []byte{}, nil)
	require.ErrorIs(t, err, ErrHPKEUnsupportedKey)
}

func TestHPKEInfoMismatch(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	pub := priv.PublicKey()

	plaintext := []byte("test info mismatch")

	// 加密时使用 info1
	enc, ciphertext, err := HPKESeal(HPKE_X25519_HKDF_SHA256_AES_256_GCM, pub, plaintext, []byte("info1"))
	require.NoError(t, err)

	// 解密时使用 info2（不匹配）
	_, err = HPKEOpen(HPKE_X25519_HKDF_SHA256_AES_256_GCM, priv, enc, ciphertext, []byte("info2"))
	require.ErrorIs(t, err, ErrHPKEOpenFailed, "info mismatch should cause decryption failure")
}

func TestHPKETamperedCiphertext(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	pub := priv.PublicKey()

	plaintext := []byte("test tampering")
	info := []byte("context")

	enc, ciphertext, err := HPKESeal(HPKE_X25519_HKDF_SHA256_AES_256_GCM, pub, plaintext, info)
	require.NoError(t, err)

	// 篡改密文
	if len(ciphertext) > 0 {
		ciphertext[0] ^= 0xFF
	}

	_, err = HPKEOpen(HPKE_X25519_HKDF_SHA256_AES_256_GCM, priv, enc, ciphertext, info)
	require.ErrorIs(t, err, ErrHPKEOpenFailed, "tampered ciphertext should be rejected")
}

func TestHPKETamperedEnc(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	pub := priv.PublicKey()

	plaintext := []byte("test enc tampering")
	info := []byte("context")

	enc, ciphertext, err := HPKESeal(HPKE_X25519_HKDF_SHA256_AES_256_GCM, pub, plaintext, info)
	require.NoError(t, err)

	// 篡改 enc（临时公钥）
	if len(enc) > 0 {
		enc[0] ^= 0xFF
	}

	_, err = HPKEOpen(HPKE_X25519_HKDF_SHA256_AES_256_GCM, priv, enc, ciphertext, info)
	require.Error(t, err, "tampered enc should cause failure")
	// enc 篡改可能导致 Setup 失败或 Open 失败，具体错误可能是 ErrHPKEOpenFailed 或其他
}

func TestHPKEWrongPrivateKey(t *testing.T) {
	// 生成两个不同的密钥对
	priv1, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	pub1 := priv1.PublicKey()

	priv2, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)

	plaintext := []byte("test wrong private key")
	info := []byte("context")

	// 使用 pub1 加密
	enc, ciphertext, err := HPKESeal(HPKE_X25519_HKDF_SHA256_AES_256_GCM, pub1, plaintext, info)
	require.NoError(t, err)

	// 使用 priv2（错误的私钥）解密
	_, err = HPKEOpen(HPKE_X25519_HKDF_SHA256_AES_256_GCM, priv2, enc, ciphertext, info)
	require.ErrorIs(t, err, ErrHPKEOpenFailed, "wrong private key should fail decryption")
}

func TestHPKEMultipleEncryptions(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	pub := priv.PublicKey()

	plaintext := []byte("same plaintext, different encryptions")
	info := []byte("context")

	// 同一明文加密两次，应该产生不同的密文（临时密钥对）
	enc1, ct1, err := HPKESeal(HPKE_X25519_HKDF_SHA256_AES_256_GCM, pub, plaintext, info)
	require.NoError(t, err)

	enc2, ct2, err := HPKESeal(HPKE_X25519_HKDF_SHA256_AES_256_GCM, pub, plaintext, info)
	require.NoError(t, err)

	// enc 应该不同（不同的临时密钥对）
	require.NotEqual(t, enc1, enc2, "ephemeral public keys should differ")

	// 密文也应该不同
	require.NotEqual(t, ct1, ct2, "ciphertexts should differ")

	// 但两个密文都应该能正确解密
	dec1, err := HPKEOpen(HPKE_X25519_HKDF_SHA256_AES_256_GCM, priv, enc1, ct1, info)
	require.NoError(t, err)
	require.Equal(t, plaintext, dec1)

	dec2, err := HPKEOpen(HPKE_X25519_HKDF_SHA256_AES_256_GCM, priv, enc2, ct2, info)
	require.NoError(t, err)
	require.Equal(t, plaintext, dec2)
}

func TestHPKEConcurrent(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	pub := priv.PublicKey()

	// 并发测试（确保线程安全）
	const goroutines = 10
	const iterations = 100

	done := make(chan bool, goroutines)

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			for j := 0; j < iterations; j++ {
				plaintext := []byte("concurrent test")
				info := []byte("context")

				enc, ciphertext, err := HPKESeal(HPKE_X25519_HKDF_SHA256_AES_256_GCM, pub, plaintext, info)
				if err != nil {
					t.Errorf("goroutine %d iteration %d: seal failed: %v", id, j, err)
					done <- false
					return
				}

				decrypted, err := HPKEOpen(HPKE_X25519_HKDF_SHA256_AES_256_GCM, priv, enc, ciphertext, info)
				if err != nil {
					t.Errorf("goroutine %d iteration %d: open failed: %v", id, j, err)
					done <- false
					return
				}

				if string(decrypted) != string(plaintext) {
					t.Errorf("goroutine %d iteration %d: plaintext mismatch", id, j)
					done <- false
					return
				}
			}
			done <- true
		}(i)
	}

	// 等待所有 goroutine 完成
	for i := 0; i < goroutines; i++ {
		<-done
	}
}

// BenchmarkHPKESeal 基准测试加密性能
func BenchmarkHPKESeal(b *testing.B) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(b, err)
	pub := priv.PublicKey()

	plaintext := make([]byte, 1024) // 1KB
	info := []byte("benchmark")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = HPKESeal(HPKE_X25519_HKDF_SHA256_AES_256_GCM, pub, plaintext, info)
	}
}

// BenchmarkHPKEOpen 基准测试解密性能
func BenchmarkHPKEOpen(b *testing.B) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(b, err)
	pub := priv.PublicKey()

	plaintext := make([]byte, 1024) // 1KB
	info := []byte("benchmark")

	enc, ciphertext, err := HPKESeal(HPKE_X25519_HKDF_SHA256_AES_256_GCM, pub, plaintext, info)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = HPKEOpen(HPKE_X25519_HKDF_SHA256_AES_256_GCM, priv, enc, ciphertext, info)
	}
}

// TestHPKE_AES128Variant 验证 AES-128-GCM 变体可用。
func TestHPKE_AES128Variant(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	pub := priv.PublicKey()

	plaintext := []byte("AES-128-GCM variant test")
	info := []byte("aes128-context")

	// 使用 AES-128-GCM suite
	enc, ciphertext, err := HPKESeal(HPKE_X25519_HKDF_SHA256_AES_128_GCM, pub, plaintext, info)
	require.NoError(t, err)
	require.NotEmpty(t, enc)
	require.NotEmpty(t, ciphertext)

	// 解密验证
	decrypted, err := HPKEOpen(HPKE_X25519_HKDF_SHA256_AES_128_GCM, priv, enc, ciphertext, info)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)
}

// TestHPKE_BothVariantsInteroperability 验证两个 suite 变体独立工作。
func TestHPKE_BothVariantsInteroperability(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	pub := priv.PublicKey()

	plaintext := []byte("cross-variant test")
	info := []byte("shared-context")

	// AES-128 加密
	enc128, ct128, err := HPKESeal(HPKE_X25519_HKDF_SHA256_AES_128_GCM, pub, plaintext, info)
	require.NoError(t, err)

	// AES-256 加密
	enc256, ct256, err := HPKESeal(HPKE_X25519_HKDF_SHA256_AES_256_GCM, pub, plaintext, info)
	require.NoError(t, err)

	// 各自解密
	dec128, err := HPKEOpen(HPKE_X25519_HKDF_SHA256_AES_128_GCM, priv, enc128, ct128, info)
	require.NoError(t, err)
	require.Equal(t, plaintext, dec128)

	dec256, err := HPKEOpen(HPKE_X25519_HKDF_SHA256_AES_256_GCM, priv, enc256, ct256, info)
	require.NoError(t, err)
	require.Equal(t, plaintext, dec256)

	// 交叉解密应失败（suite 不匹配）
	_, err = HPKEOpen(HPKE_X25519_HKDF_SHA256_AES_256_GCM, priv, enc128, ct128, info)
	require.Error(t, err, "AES-256 suite should not decrypt AES-128 ciphertext")

	_, err = HPKEOpen(HPKE_X25519_HKDF_SHA256_AES_128_GCM, priv, enc256, ct256, info)
	require.Error(t, err, "AES-128 suite should not decrypt AES-256 ciphertext")
}

// TestHPKE_RFC9180Vector 验证 RFC 9180 §A.1 官方测试向量（AES-128-GCM）。
// 向量来源：https://www.rfc-editor.org/rfc/rfc9180#appendix-A.1
func TestHPKE_RFC9180Vector(t *testing.T) {
	// RFC 9180 §A.1 测试向量
	// KEM: DHKEM(X25519, HKDF-SHA256) = 0x0020
	// KDF: HKDF-SHA256 = 0x0001
	// AEAD: AES-128-GCM = 0x0001
	
	// 接收方私钥（skRm）
	skRm, err := hex.DecodeString("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8")
	require.NoError(t, err)
	
	// 临时公钥（enc）
	enc, err := hex.DecodeString("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431")
	require.NoError(t, err)
	
	// info: "Ode on a Grecian Urn"
	info, err := hex.DecodeString("4f6465206f6e2061204772656369616e2055726e")
	require.NoError(t, err)
	
	// aad: "Count-0"
	aad, err := hex.DecodeString("436f756e742d30")
	require.NoError(t, err)
	
	// 明文: "Beauty is truth, truth beauty"
	pt, err := hex.DecodeString("4265617574792069732074727574682c20747275746820626561757479")
	require.NoError(t, err)
	
	// 密文（ct）
	ct, err := hex.DecodeString("f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a")
	require.NoError(t, err)
	
	// 使用 AES-128-GCM suite 解密
	suite := HPKE_X25519_HKDF_SHA256_AES_128_GCM
	
	// 注意：RFC 向量的密文包含 AAD，但我们的 API 当前固定 aad=nil
	// 这里直接调用 CIRCL 底层 API 验证向量
	hpkeSuite, err := hpkeResolveSuite(suite)
	require.NoError(t, err)
	
	kemScheme := hpke.KEM_X25519_HKDF_SHA256.Scheme()
	skR, err := kemScheme.UnmarshalBinaryPrivateKey(skRm)
	require.NoError(t, err)
	
	receiver, err := hpkeSuite.NewReceiver(skR, info)
	require.NoError(t, err)
	
	opener, err := receiver.Setup(enc)
	require.NoError(t, err)
	
	// 解密（带 AAD）
	decrypted, err := opener.Open(ct, aad)
	require.NoError(t, err)
	require.Equal(t, pt, decrypted, "RFC 9180 §A.1 vector decryption should match")
}