package crypto_test

import (
	crypto "github.com/charlienet/go-crypto"
	"github.com/charlienet/go-crypto/hash"
	"github.com/charlienet/go-crypto/hmac"
	"github.com/charlienet/go-crypto/kdf"
	_ "github.com/charlienet/go-crypto/engines" // 一键导入所有引擎
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSymmetricEncryptionIntegration(t *testing.T) {
	testCases := []struct {
		name        string
		algorithm   crypto.Algorithm
		mode        crypto.Mode
		keySize     int
		plaintext   string
		insecure    bool
	}{
		{"AES128-CBC", crypto.AES128, crypto.CBC, 16, "Hello World!", false},
		{"AES192-CBC", crypto.AES192, crypto.CBC, 24, "Hello World!", false},
		{"AES256-CBC", crypto.AES256, crypto.CBC, 32, "Hello World!", false},
		{"AES128-ECB", crypto.AES128, crypto.ECB, 16, "Hello World!", true},
		{"AES128-CTR", crypto.AES128, crypto.CTR, 16, "Hello World!", false},
		{"AES128-CFB", crypto.AES128, crypto.CFB, 16, "Hello World!", false},
		{"AES128-OFB", crypto.AES128, crypto.OFB, 16, "Hello World!", false},
		{"AES128-GCM", crypto.AES128, crypto.GCM, 16, "Hello World!", false},
		{"SM4-CBC", crypto.SM4, crypto.CBC, 16, "Hello World!", false},
		{"SM4-ECB", crypto.SM4, crypto.ECB, 16, "Hello World!", true},
		{"SM4-CTR", crypto.SM4, crypto.CTR, 16, "Hello World!", false},
		{"SM4-CFB", crypto.SM4, crypto.CFB, 16, "Hello World!", false},
		{"SM4-OFB", crypto.SM4, crypto.OFB, 16, "Hello World!", false},
		{"SM4-GCM", crypto.SM4, crypto.GCM, 16, "Hello World!", false},
		{"DES-CBC", crypto.DES, crypto.CBC, 8, "Hello World!", true},
		{"TripleDES-CBC", crypto.TripleDES, crypto.CBC, 24, "Hello World!", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key := make([]byte, tc.keySize)
			for i := range key {
				key[i] = byte(i % 256)
			}

			opts := []crypto.Option{
				crypto.WithKey(key),
			}

			if tc.insecure {
				opts = append(opts, crypto.WithInsecureAlgorithms())
			}

			switch tc.mode {
			case crypto.ECB:
				// ECB mode doesn't use IV
			case crypto.GCM:
				// GCM mode uses nonce, not IV
				nonce := make([]byte, 12) // GCM nonce is always 12 bytes
				for i := range nonce {
					nonce[i] = byte((i + 10) % 256)
				}
				opts = append(opts, crypto.WithNonce(nonce))
			default:
				// Add IV for modes that require it
				iv := make([]byte, tc.algorithm.BlockSize())
				for i := range iv {
					iv[i] = byte((i + 10) % 256)
				}
				opts = append(opts, crypto.WithIV(iv))
			}

			encryptor, err := crypto.NewEncryptor(tc.algorithm, tc.mode, opts...)
			require.NoError(t, err)

			encrypted, err := encryptor.Encrypt([]byte(tc.plaintext))
			require.NoError(t, err)

			decrypted, err := encryptor.Decrypt(encrypted)
			require.NoError(t, err)
			assert.Equal(t, tc.plaintext, string(decrypted))

			// Test direct Encrypt/Decrypt functions
			encrypted2, err := crypto.Encrypt(tc.algorithm, tc.mode, []byte(tc.plaintext), opts...)
			require.NoError(t, err)

			decrypted2, err := crypto.Decrypt(tc.algorithm, tc.mode, encrypted2, opts...)
			require.NoError(t, err)
			assert.Equal(t, tc.plaintext, string(decrypted2))
		})
	}
}

func TestAsymmetricSignIntegration(t *testing.T) {
	testCases := []struct {
		name      string
		algorithm crypto.AsymmetricAlgorithm
		message   string
	}{
		{"RSA-Sign", crypto.RSA, "Test message for RSA signing"},
		{"ECDSA-Sign", crypto.ECDSA, "Test message for ECDSA signing"},
		{"ED25519-Sign", crypto.ED25519, "Test message for ED25519 signing"},
		{"SM2-Sign", crypto.SM2, "Test message for SM2 signing"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			keyPair, err := crypto.GenerateKeyPair(tc.algorithm)
			require.NoError(t, err)

			// Create signer with private key
			signer, err := crypto.NewAsymmetric(tc.algorithm, crypto.WithPrivateKeyObject(keyPair.PrivateKey))
			require.NoError(t, err)

			signature, err := signer.Sign([]byte(tc.message))
			require.NoError(t, err)

			// Create verifier with public key
			verifier, err := crypto.NewAsymmetric(tc.algorithm, crypto.WithPublicKeyObject(keyPair.PublicKey))
			require.NoError(t, err)

			valid := verifier.Verify([]byte(tc.message), signature)
			assert.True(t, valid, "Signature verification should pass")

			// Test with wrong message
			invalidValid := verifier.Verify([]byte("Wrong message"), signature)
			assert.False(t, invalidValid, "Signature verification should fail with wrong message")
		})
	}
}

func TestKeyAgreementIntegration(t *testing.T) {
	testCases := []struct {
		name      string
		algorithm crypto.KeyAgreementAlgorithm
	}{
		{"ECDH-KeyAgreement", crypto.ECDH},
		{"X25519-KeyAgreement", crypto.X25519},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Party A creates key agreement instance
			kaA, err := crypto.NewKeyAgreement(tc.algorithm)
			require.NoError(t, err)

			// Party A generates key pair
			keyPairA, err := kaA.GenerateKey()
			require.NoError(t, err)

			// Party B creates key agreement instance
			kaB, err := crypto.NewKeyAgreement(tc.algorithm)
			require.NoError(t, err)

			// Party B generates key pair
			keyPairB, err := kaB.GenerateKey()
			require.NoError(t, err)

			// Party A derives shared secret using its private key and party B's public key
			sharedSecretA, err := kaA.DeriveSharedSecret(keyPairB.PublicKey)
			require.NoError(t, err)

			// Party B derives shared secret using its private key and party A's public key
			sharedSecretB, err := kaB.DeriveSharedSecret(keyPairA.PublicKey)
			require.NoError(t, err)

			// Both parties should have the same shared secret
			assert.Equal(t, sharedSecretA, sharedSecretB, "Shared secrets should match between both parties")
		})
	}
}

func TestHashIntegration(t *testing.T) {
	testCases := []struct {
		name      string
		algorithm string
		message   string
	}{
		{"SHA256-Hash", "SHA256", "Test message for SHA256"},
		{"SHA512-Hash", "SHA512", "Test message for SHA512"},
		{"SM3-Hash", "SM3", "Test message for SM3"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Get hash function
			hashFunc, err := hash.ByName(tc.algorithm)
			require.NoError(t, err)
			
			// Test hash function
			digest1 := hashFunc([]byte(tc.message))

			// Test New hasher
			hasher, err := hash.New(tc.algorithm)
			require.NoError(t, err)
			
			result, err := hasher.Sign([]byte(tc.message))
			require.NoError(t, err)
			digest2 := result

			assert.Equal(t, digest1.Bytes(), digest2.Bytes(), "Direct hash and New hasher should produce same result")

			// Test with different input
			differentDigest := hashFunc([]byte("Different message"))
			assert.NotEqual(t, digest1.Bytes(), differentDigest.Bytes(), "Different messages should produce different hashes")
		})
	}
}

func TestHMACIntegration(t *testing.T) {
	testCases := []struct {
		name      string
		algorithm string
		message   string
		key       string
	}{
		{"HMAC-SHA256", "HMACSHA256", "Test message for HMAC-SHA256", "secret-key"},
		{"HMAC-SM3", "HMACSM3", "Test message for HMAC-SM3", "secret-key"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Get HMAC function
			hmacFunc, err := hmac.ByName(tc.algorithm)
			require.NoError(t, err)
			
			// Test HMAC function
			mac1 := hmacFunc([]byte(tc.key), []byte(tc.message))

			// Test New MAC
			macObj, err := hmac.New(tc.algorithm, []byte(tc.key))
			require.NoError(t, err)
			
			result, err := macObj.Sign([]byte(tc.message))
			require.NoError(t, err)
			mac2 := result

			assert.Equal(t, mac1.Bytes(), mac2.Bytes(), "Direct MAC and New MAC should produce same result")

			// Test verification
			isValid := macObj.Verify([]byte(tc.message), mac1.Bytes())
			assert.True(t, isValid, "HMAC verification should pass")

			// Test with wrong key
			wrongHmacFunc, err := hmac.ByName(tc.algorithm)
			require.NoError(t, err)
			wrongMac := wrongHmacFunc([]byte("wrong-key"), []byte(tc.message))
			isInvalid := macObj.Verify([]byte(tc.message), wrongMac.Bytes())
			assert.False(t, isInvalid, "HMAC verification should fail with wrong key")
		})
	}
}

func TestEndToEndKDFToSymmetric(t *testing.T) {
	password := []byte("my-secret-password")
	salt := []byte("random-salt-12345")
	keyLen := 32 // 256 bits for AES

	// Derive key using KDF
	derivedKey, err := kdf.DeriveKey(password, salt, keyLen)
	require.NoError(t, err)
	assert.Len(t, derivedKey, keyLen, "Derived key should have expected length")

	// Use derived key for symmetric encryption
	plaintext := "Hello from KDF-to-symmetric integration test!"
	
	// Add IV for CBC mode
	iv := make([]byte, crypto.AES256.BlockSize())
	for i := range iv {
		iv[i] = byte(i % 256)
	}

	encrypted, err := crypto.Encrypt(crypto.AES256, crypto.CBC, []byte(plaintext), 
		crypto.WithKey(derivedKey),
		crypto.WithIV(iv),
	)
	require.NoError(t, err)

	decrypted, err := crypto.Decrypt(crypto.AES256, crypto.CBC, encrypted,
		crypto.WithKey(derivedKey),
		crypto.WithIV(iv),
	)
	require.NoError(t, err)
	assert.Equal(t, plaintext, string(decrypted))
}

func TestEndToEndKeyAgreementToSymmetric(t *testing.T) {
	// Party A creates key agreement instance
	kaA, err := crypto.NewKeyAgreement(crypto.ECDH)
	require.NoError(t, err)

	// Party A generates key pair
	keyPairA, err := kaA.GenerateKey()
	require.NoError(t, err)

	// Party B creates key agreement instance
	kaB, err := crypto.NewKeyAgreement(crypto.ECDH)
	require.NoError(t, err)

	// Party B generates key pair
	keyPairB, err := kaB.GenerateKey()
	require.NoError(t, err)

	// Both parties derive the same shared secret
	sharedSecretA, err := kaA.DeriveSharedSecret(keyPairB.PublicKey)
	require.NoError(t, err)

	sharedSecretB, err := kaB.DeriveSharedSecret(keyPairA.PublicKey)
	require.NoError(t, err)

	assert.Equal(t, sharedSecretA, sharedSecretB, "Both parties should derive the same shared secret")

	// Use the shared secret as encryption key
	plaintext := "Hello from key-agreement-to-symmetric integration test!"

	// Truncate or extend the shared secret to a valid key length (AES-256 requires 32 bytes)
	var aesKey []byte
	if len(sharedSecretA) >= 32 {
		aesKey = sharedSecretA[:32] // Take first 32 bytes for AES-256
	} else {
		// Extend the key if needed (in real scenario, use proper key derivation)
		aesKey = make([]byte, 32)
		copy(aesKey, sharedSecretA)
	}

	// Add IV for CBC mode
	iv := make([]byte, crypto.AES256.BlockSize())
	for i := range iv {
		iv[i] = byte(i % 256)
	}

	// Encrypt using the shared key
	encrypted, err := crypto.Encrypt(crypto.AES256, crypto.CBC, []byte(plaintext),
		crypto.WithKey(aesKey),
		crypto.WithIV(iv),
	)
	require.NoError(t, err)

	// Decrypt using the same shared key
	decrypted, err := crypto.Decrypt(crypto.AES256, crypto.CBC, encrypted,
		crypto.WithKey(aesKey),
		crypto.WithIV(iv),
	)
	require.NoError(t, err)
	assert.Equal(t, plaintext, string(decrypted))
}