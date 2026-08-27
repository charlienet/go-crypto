package crypto_test

// Encryptor 可复用对称加密对象测试（package crypto_test + blank import
// symmetric）：构造错误路径、单实例多轮往返、nonce/IV 不重复、双轨互解、
// 与低层互解、篡改与错误、并发 -race、语义契约（快照冻结/输入独立性）。

import (
	"bytes"
	"fmt"
	"sync"
	"testing"

	"github.com/charlienet/go-crypto/crypto"

	_ "github.com/charlienet/go-crypto/crypto/symmetric"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==================== ① 构造错误路径（表驱动） ====================

func TestEncryptor_ConstructionErrors(t *testing.T) {
	key16 := make([]byte, 16)
	cases := []struct {
		name string
		alg  crypto.Algorithm
		mode crypto.Mode
		opts []crypto.Option
		want error
	}{
		{"未知算法", crypto.Algorithm(99), crypto.GCM, []crypto.Option{crypto.WithKey(key16)}, crypto.ErrUnknownAlgorithm},
		{"未知模式", crypto.AES128, crypto.Mode(99), []crypto.Option{crypto.WithKey(key16)}, crypto.ErrUnknownMode},
		{"密钥缺源", crypto.AES128, crypto.GCM, nil, crypto.ErrKeyRequired},
		{"密钥缺源", crypto.AES128, crypto.GCM, nil, crypto.ErrKeyRequired},
		{"坏 hex", crypto.AES128, crypto.GCM, []crypto.Option{crypto.WithHexPassword("zz")}, crypto.ErrInvalidHexPassword},
		{"坏 base64", crypto.AES128, crypto.GCM, []crypto.Option{crypto.WithBase64Password("!!!not-base64!!!")}, crypto.ErrInvalidBase64Password},
		{"密钥长度", crypto.AES256, crypto.GCM, []crypto.Option{crypto.WithKey(make([]byte, 16))}, crypto.ErrInvalidKeyLength},
		{"GCM×DES", crypto.DES, crypto.GCM, []crypto.Option{crypto.WithKey(make([]byte, 8)), crypto.WithInsecureAlgorithms()}, crypto.ErrIncompatibleAlgorithmMode},
		{"CBC×WithAAD", crypto.AES128, crypto.CBC, []crypto.Option{crypto.WithKey(key16), crypto.WithAAD([]byte("aad"))}, crypto.ErrAADNotSupported},
		{"GCM×WithPadding", crypto.AES128, crypto.GCM, []crypto.Option{crypto.WithKey(key16), crypto.WithPadding(crypto.NoPadding{})}, crypto.ErrPaddingNotSupported},
		{"IV 长度", crypto.AES128, crypto.CBC, []crypto.Option{crypto.WithKey(key16), crypto.WithIV(make([]byte, 15))}, crypto.ErrInvalidIVLength},
		{"nonce 长度", crypto.AES128, crypto.GCM, []crypto.Option{crypto.WithKey(key16), crypto.WithNonce(make([]byte, 11))}, crypto.ErrInvalidNonceLength},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := crypto.NewEncryptor(tc.alg, tc.mode, tc.opts...)
			assert.ErrorIs(t, err, tc.want)
		})
	}
}

// ==================== ② 单实例多轮往返（六模式） ====================

func TestEncryptor_RoundTrip_MultiRound(t *testing.T) {
	modes := []crypto.Mode{crypto.GCM, crypto.CBC, crypto.ECB, crypto.CFB, crypto.OFB, crypto.CTR}

	for _, mode := range modes {
		t.Run(mode.String(), func(t *testing.T) {
			opts := []crypto.Option{crypto.WithKey(make([]byte, 16))}
			if mode == crypto.ECB {
				opts = append(opts, crypto.WithInsecureAlgorithms())
			}
			e, err := crypto.NewEncryptor(crypto.AES128, mode, opts...)
			require.NoError(t, err)

			// 同一实例连续多轮 Encrypt→Decrypt 还原（长度变化覆盖填充边界）
			for i := 0; i < 5; i++ {
				pt := []byte(fmt.Sprintf("round %d payload %d", i, i))
				ct, err := e.Encrypt(pt)
				require.NoError(t, err, "第 %d 轮 Encrypt", i)
				got, err := e.Decrypt(ct)
				require.NoError(t, err, "第 %d 轮 Decrypt", i)
				assert.Equal(t, pt, got)
			}
		})
	}
}

// ==================== ③ nonce/IV 不重复（同实例连续 N 轮前缀互异） ====================

func TestEncryptor_NonceIV_Unique(t *testing.T) {
	pt := []byte("unique prefix check payload")
	key := make([]byte, 16)

	// GCM：前缀 12B nonce 互异
	t.Run("GCM", func(t *testing.T) {
		e, err := crypto.NewEncryptor(crypto.AES128, crypto.GCM, crypto.WithKey(key))
		require.NoError(t, err)
		seen := make(map[string]bool)
		for i := 0; i < 8; i++ {
			ct, err := e.Encrypt(pt)
			require.NoError(t, err)
			prefix := string(ct[:12])
			assert.False(t, seen[prefix], "GCM nonce 不得重复（第 %d 轮）", i)
			seen[prefix] = true
		}
	})

	// CBC/CFB/OFB/CTR：前缀 16B（块大小）互异
	for _, mode := range []crypto.Mode{crypto.CBC, crypto.CFB, crypto.OFB, crypto.CTR} {
		t.Run(mode.String(), func(t *testing.T) {
			e, err := crypto.NewEncryptor(crypto.AES128, mode, crypto.WithKey(key))
			require.NoError(t, err)
			seen := make(map[string]bool)
			for i := 0; i < 8; i++ {
				ct, err := e.Encrypt(pt)
				require.NoError(t, err)
				prefix := string(ct[:16])
				assert.False(t, seen[prefix], "%s IV/counter 不得重复（第 %d 轮）", mode, i)
				seen[prefix] = true
			}
		})
	}

	// ECB：无前缀，仅断言密文为块大小整数倍且含 PKCS7 填充
	t.Run("ECB", func(t *testing.T) {
		e, err := crypto.NewEncryptor(crypto.AES128, crypto.ECB, crypto.WithKey(key), crypto.WithInsecureAlgorithms())
		require.NoError(t, err)
		ct, err := e.Encrypt(pt)
		require.NoError(t, err)
		assert.Equal(t, 0, len(ct)%16, "ECB 无前缀，密文应为块大小整数倍")
		assert.True(t, len(ct) > len(pt), "ECB 含 PKCS7 填充")
	})
}

// ==================== ④ 双轨互解矩阵 ====================

func TestEncryptor_CrossInterop(t *testing.T) {
	modes := []crypto.Mode{crypto.GCM, crypto.CBC, crypto.ECB, crypto.CFB, crypto.OFB, crypto.CTR}
	key := make([]byte, 16)
	iv := bytes.Repeat([]byte{0xAB}, 16)
	nonce := bytes.Repeat([]byte{0x42}, 12)
	pt := []byte("cross interop between Encryptor and package-level API")

	for _, mode := range modes {
		t.Run(mode.String()+"_默认路径", func(t *testing.T) {
			opts := []crypto.Option{crypto.WithKey(key)}
			if mode == crypto.ECB {
				opts = append(opts, crypto.WithInsecureAlgorithms())
			}
			e, err := crypto.NewEncryptor(crypto.AES128, mode, opts...)
			require.NoError(t, err)

			// Encryptor.Encrypt → 根包 Decrypt
			ct, err := e.Encrypt(pt)
			require.NoError(t, err)
			optsDecrypt := []crypto.Option{crypto.WithKey(key)}
			if mode == crypto.ECB {
				optsDecrypt = append(optsDecrypt, crypto.WithInsecureAlgorithms())
			}
			got, err := crypto.Decrypt(crypto.AES128, mode, ct, optsDecrypt...)
			require.NoError(t, err)
			assert.Equal(t, pt, got, "Encryptor→根包 Decrypt")

			// 根包 Encrypt → Encryptor.Decrypt
			ct, err = crypto.Encrypt(crypto.AES128, mode, pt, optsDecrypt...)
			require.NoError(t, err)
			got, err = e.Decrypt(ct)
			require.NoError(t, err)
			assert.Equal(t, pt, got, "根包 Encrypt→Encryptor")
		})

		t.Run(mode.String()+"_固定IV路径", func(t *testing.T) {
			var fixedOpts []crypto.Option
			if mode == crypto.GCM {
				fixedOpts = []crypto.Option{crypto.WithNonce(nonce)}
			} else if mode != crypto.ECB {
				fixedOpts = []crypto.Option{crypto.WithIV(iv)}
			}

			opts := append([]crypto.Option{crypto.WithKey(key)}, fixedOpts...)
			if mode == crypto.ECB {
				opts = append(opts, crypto.WithInsecureAlgorithms())
			}
			e, err := crypto.NewEncryptor(crypto.AES128, mode, opts...)
			require.NoError(t, err)

			// Encryptor.Encrypt → 根包 Decrypt（对称传固定 IV/nonce）
			ct, err := e.Encrypt(pt)
			require.NoError(t, err)
			optsDecryptFixed := append([]crypto.Option{crypto.WithKey(key)}, fixedOpts...)
			if mode == crypto.ECB {
				optsDecryptFixed = append(optsDecryptFixed, crypto.WithInsecureAlgorithms())
			}
			got, err := crypto.Decrypt(crypto.AES128, mode, ct, optsDecryptFixed...)
			require.NoError(t, err)
			assert.Equal(t, pt, got, "Encryptor→根包 Decrypt（固定 IV/nonce）")

			// 根包 Encrypt → Encryptor.Decrypt（对称传固定 IV/nonce）
			optsEncryptFixed := append([]crypto.Option{crypto.WithKey(key)}, fixedOpts...)
			if mode == crypto.ECB {
				optsEncryptFixed = append(optsEncryptFixed, crypto.WithInsecureAlgorithms())
			}
			ct, err = crypto.Encrypt(crypto.AES128, mode, pt, optsEncryptFixed...)
			require.NoError(t, err)
			got, err = e.Decrypt(ct)
			require.NoError(t, err)
			assert.Equal(t, pt, got, "根包 Encrypt→Encryptor（固定 IV/nonce）")
		})
	}
}

// ==================== ⑤ 与低层互解 ====================

func TestEncryptor_LowLevelInterop(t *testing.T) {
	key := []byte("0123456789abcdef")
	pt := []byte("low level interop with GCM")

	e, err := crypto.NewEncryptor(crypto.AES128, crypto.GCM, crypto.WithKey(key))
	require.NoError(t, err)

	// Encryptor GCM 输出 → 低层 NewGCM(nil, EmbedNonce()).Decrypt
	ct, err := e.Encrypt(pt)
	require.NoError(t, err)
	c, err := crypto.NewCipher("AES-128", key)
	require.NoError(t, err)
	gcm, err := c.NewGCM(nil, crypto.EmbedNonce())
	require.NoError(t, err)
	got, err := gcm.Decrypt(ct)
	require.NoError(t, err)
	assert.Equal(t, pt, []byte(got), "低层 NewGCM(EmbedNonce) 应能解 Encryptor 输出")

	// 低层 NewGCMWithRandomNonce 输出 → Encryptor.Decrypt
	gcm2, err := c.NewGCMWithRandomNonce()
	require.NoError(t, err)
	ct2, err := gcm2.Encrypt(pt)
	require.NoError(t, err)
	got2, err := e.Decrypt(ct2)
	require.NoError(t, err)
	assert.Equal(t, pt, got2, "Encryptor 应能解低层 NewGCMWithRandomNonce 输出")
}

// ==================== ⑥ 篡改与错误 ====================

func TestEncryptor_TamperErrors(t *testing.T) {
	key := make([]byte, 16)
	pt := []byte("tamper and error mapping for Encryptor")

	t.Run("GCM_篡改认证失败", func(t *testing.T) {
		e, err := crypto.NewEncryptor(crypto.AES128, crypto.GCM, crypto.WithKey(key))
		require.NoError(t, err)
		ct, err := e.Encrypt(pt)
		require.NoError(t, err)
		tampered := append([]byte(nil), ct...)
		tampered[len(tampered)-1] ^= 0xFF // 篡改 tag
		_, err = e.Decrypt(tampered)
		assert.ErrorIs(t, err, crypto.ErrAuthenticationFailed)
	})

	t.Run("GCM_密文过短", func(t *testing.T) {
		e, err := crypto.NewEncryptor(crypto.AES128, crypto.GCM, crypto.WithKey(key))
		require.NoError(t, err)
		_, err = e.Decrypt([]byte("short"))
		assert.ErrorIs(t, err, crypto.ErrCiphertextTooShort)
	})

	t.Run("CBC_非对齐", func(t *testing.T) {
		e, err := crypto.NewEncryptor(crypto.AES128, crypto.CBC, crypto.WithKey(key))
		require.NoError(t, err)
		_, err = e.Decrypt(make([]byte, 17))
		assert.ErrorIs(t, err, crypto.ErrCiphertextNotAligned)
	})

	t.Run("CBC_填充错误", func(t *testing.T) {
		e, err := crypto.NewEncryptor(crypto.AES128, crypto.CBC, crypto.WithKey(key))
		require.NoError(t, err)
		ct, err := e.Encrypt(pt)
		require.NoError(t, err)
		tampered := append([]byte(nil), ct...)
		tampered[len(tampered)-2] ^= 0xFF // 篡改 padding 区
		_, err = e.Decrypt(tampered)
		assert.ErrorIs(t, err, crypto.ErrInvalidPadding)
	})

	t.Run("GCM_AAD错配", func(t *testing.T) {
		e1, err := crypto.NewEncryptor(crypto.AES128, crypto.GCM, crypto.WithKey(key), crypto.WithAAD([]byte("aad1")))
		require.NoError(t, err)
		e2, err := crypto.NewEncryptor(crypto.AES128, crypto.GCM, crypto.WithKey(key), crypto.WithAAD([]byte("aad2")))
		require.NoError(t, err)
		ct, err := e1.Encrypt(pt)
		require.NoError(t, err)
		_, err = e2.Decrypt(ct)
		assert.ErrorIs(t, err, crypto.ErrAuthenticationFailed, "AAD 错配必须认证失败")
	})
}

// ==================== ⑦ 并发 -race（单实例多 goroutine 混合加解密） ====================

func TestEncryptor_Concurrent(t *testing.T) {
	modes := []crypto.Mode{crypto.GCM, crypto.CBC, crypto.ECB, crypto.CFB, crypto.OFB, crypto.CTR}

	for _, mode := range modes {
		t.Run(mode.String(), func(t *testing.T) {
			opts := []crypto.Option{crypto.WithKey(make([]byte, 16))}
			if mode == crypto.ECB {
				opts = append(opts, crypto.WithInsecureAlgorithms())
			}
			e, err := crypto.NewEncryptor(crypto.AES128, mode, opts...)
			require.NoError(t, err)
			pt := []byte("concurrent Encryptor race check payload")

			var wg sync.WaitGroup
			for i := 0; i < 8; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for j := 0; j < 100; j++ {
						ct, err := e.Encrypt(pt)
						assert.NoError(t, err)
						got, err := e.Decrypt(ct)
						assert.NoError(t, err)
						assert.Equal(t, pt, got)
					}
				}()
			}
			wg.Wait()
		})
	}
}

// ==================== ⑧ 语义契约（Algorithm/Mode、快照冻结、输入独立性） ====================

func TestEncryptor_SemanticContract(t *testing.T) {
	key := []byte("0123456789abcdef")
	iv := []byte("abcdef0123456789")
	nonce := []byte("0123456789ab")
	pt := []byte("semantic contract payload")

	t.Run("Algorithm_Mode", func(t *testing.T) {
		e, err := crypto.NewEncryptor(crypto.AES128, crypto.CBC, crypto.WithKey(key))
		require.NoError(t, err)
		assert.Equal(t, crypto.AES128, e.Algorithm())
		assert.Equal(t, crypto.CBC, e.Mode())
	})

	t.Run("构造后修改opts切片不影响对象", func(t *testing.T) {
		// 固定 IV + 固定密钥：构造后修改源切片，同对象两次加密输出必须一致
		e, err := crypto.NewEncryptor(crypto.AES128, crypto.CBC, crypto.WithKey(key), crypto.WithIV(iv))
		require.NoError(t, err)
		key[0] ^= 0xFF
		iv[0] ^= 0xFF
		enc1, err := e.Encrypt(pt)
		require.NoError(t, err)
		enc2, err := e.Encrypt(pt)
		require.NoError(t, err)
		assert.Equal(t, enc1, enc2, "冻结 IV/Key 快照后两次加密输出必须一致")
		got, err := e.Decrypt(enc1)
		require.NoError(t, err)
		assert.Equal(t, pt, got, "冻结快照下加解密往返正常")

		// GCM 固定 nonce 同理
		e2, err := crypto.NewEncryptor(crypto.AES128, crypto.GCM, crypto.WithKey(key), crypto.WithNonce(nonce))
		require.NoError(t, err)
		nonce[0] ^= 0xFF
		enc1, err = e2.Encrypt(pt)
		require.NoError(t, err)
		enc2, err = e2.Encrypt(pt)
		require.NoError(t, err)
		assert.Equal(t, enc1, enc2, "冻结 nonce 快照后两次加密输出必须一致")
	})

	t.Run("Encrypt输出与输入无共享底层", func(t *testing.T) {
		e, err := crypto.NewEncryptor(crypto.AES128, crypto.GCM, crypto.WithKey(key))
		require.NoError(t, err)

		// 场景 A：修改输入不影响已产出的输出
		ptA := append([]byte(nil), pt...)
		encA, err := e.Encrypt(ptA)
		require.NoError(t, err)
		origEncA := append([]byte(nil), encA...)
		ptA[0] ^= 0xFF
		assert.Equal(t, origEncA, encA, "修改输入不应影响已产出的密文")

		// 场景 B：修改输出不影响输入
		ptB := append([]byte(nil), pt...)
		encB, err := e.Encrypt(ptB)
		require.NoError(t, err)
		origPtB := append([]byte(nil), ptB...)
		encB[0] ^= 0xFF
		assert.Equal(t, origPtB, ptB, "修改密文不应影响明文输入")
	})
}

// ==================== 不安全算法/模式拒绝测试 ====================

func TestInsecureAlgorithm_Refused(t *testing.T) {
	key := make([]byte, 8) // DES key
	_, err := crypto.Encrypt(crypto.DES, crypto.CBC, []byte("test"), crypto.WithKey(key))
	assert.Error(t, err)
	assert.ErrorIs(t, err, crypto.ErrInsecureAlgorithm)
}

func TestInsecureMode_Refused(t *testing.T) {
	key := make([]byte, 16) // AES-128 key
	_, err := crypto.Encrypt(crypto.AES128, crypto.ECB, []byte("test"), crypto.WithKey(key))
	assert.Error(t, err)
	assert.ErrorIs(t, err, crypto.ErrInsecureAlgorithm)
}

func TestInsecureAlgorithm_WithOptIn(t *testing.T) {
	key := make([]byte, 8) // DES key
	pt := []byte("test data!")
	ct, err := crypto.Encrypt(crypto.DES, crypto.CBC, pt, crypto.WithKey(key), crypto.WithInsecureAlgorithms())
	assert.NoError(t, err)
	got, err := crypto.Decrypt(crypto.DES, crypto.CBC, ct, crypto.WithKey(key), crypto.WithInsecureAlgorithms())
	assert.NoError(t, err)
	assert.Equal(t, pt, got)
}
