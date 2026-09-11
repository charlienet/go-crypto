package envelope

import (
	"crypto/ecdh"
	"crypto/rand"
	"testing"

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