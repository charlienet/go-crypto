package symmetric

// 六模式（GCM/CBC/ECB/CFB/OFB/CTR）协议层用例：经根包 crypto.Encrypt/
// crypto.Decrypt 调用，覆盖注册表分发链（根包 → ModeExecutor → 低层 CipherMode）。
// 断言文本与迁移前 encrypt_test.go 完全一致。

import (
	"bytes"
	"sync"
	"testing"

	"github.com/charlienet/go-crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==================== 算法×模式兼容矩阵 ====================

func TestCompatibilityMatrix(t *testing.T) {
	algs := []crypto.Algorithm{crypto.AES128, crypto.AES192, crypto.AES256, crypto.SM4, crypto.DES, crypto.TripleDES}
	modes := []crypto.Mode{crypto.ECB, crypto.CBC, crypto.CTR, crypto.CFB, crypto.OFB, crypto.GCM}
	for _, alg := range algs {
		for _, mode := range modes {
			key := make([]byte, alg.KeySize())
			opts := []crypto.Option{crypto.WithKey(key)}
			if alg == crypto.DES || alg == crypto.TripleDES || mode == crypto.ECB {
				opts = append(opts, crypto.WithInsecureAlgorithms())
			}
			_, err := crypto.Encrypt(alg, mode, []byte("compat matrix"), opts...)
			if mode == crypto.GCM && (alg == crypto.DES || alg == crypto.TripleDES) {
				assert.ErrorIs(t, err, crypto.ErrIncompatibleAlgorithmMode, "%s×%s", alg, mode)
			} else {
				assert.NoError(t, err, "%s×%s", alg, mode)
			}
		}
	}
}

// ==================== 全模式往返 + 前缀长度 ====================

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	algs := []crypto.Algorithm{crypto.AES128, crypto.SM4}
	modes := []crypto.Mode{crypto.GCM, crypto.CBC, crypto.ECB, crypto.CFB, crypto.OFB, crypto.CTR}
	plaintext := []byte("hello crypto mode api roundtrip test!") // 37B

	for _, alg := range algs {
		for _, mode := range modes {
			key := make([]byte, alg.KeySize())
			opts := []crypto.Option{crypto.WithKey(key)}
			if mode == crypto.ECB {
				opts = append(opts, crypto.WithInsecureAlgorithms())
			}
			ct, err := crypto.Encrypt(alg, mode, plaintext, opts...)
			require.NoError(t, err, "%s×%s encrypt", alg, mode)
			pt, err := crypto.Decrypt(alg, mode, ct, opts...)
			require.NoError(t, err, "%s×%s decrypt", alg, mode)
			assert.Equal(t, plaintext, pt, "%s×%s 往返", alg, mode)

			// 紧凑前缀长度断言（IV/nonce 按块大小前置）
			bs := alg.BlockSize()
			switch mode {
			case crypto.GCM:
				assert.Equal(t, len(plaintext)+28, len(ct), "GCM 前缀 12B nonce + 16B tag")
			case crypto.CBC:
				padLen := bs - len(plaintext)%bs
				assert.Equal(t, len(plaintext)+padLen+bs, len(ct), "CBC IV 前缀 + PKCS7")
			case crypto.CFB, crypto.OFB, crypto.CTR:
				assert.Equal(t, len(plaintext)+bs, len(ct), "%s 块大小前缀", mode)
			case crypto.ECB:
				assert.Equal(t, 0, len(ct)%bs, "ECB 无前缀，密文应为块大小整数倍")
				assert.True(t, len(ct) > len(plaintext), "ECB 含 PKCS7 填充")
			}
		}
	}
}

// ==================== IV：默认随机前置 / 显式无前缀 / 长度校验 ====================

func TestDefaultRandomIV_Embedded(t *testing.T) {
	key := make([]byte, 16)
	pt := []byte("random iv embedded check")
	ivSize := crypto.AES128.BlockSize()

	c1, err := crypto.Encrypt(crypto.AES128, crypto.CBC, pt, crypto.WithKey(key))
	require.NoError(t, err)
	c2, err := crypto.Encrypt(crypto.AES128, crypto.CBC, pt, crypto.WithKey(key))
	require.NoError(t, err)
	assert.Equal(t, len(c1), len(c2), "两次加密长度应一致")
	assert.NotEqual(t, c1, c2, "随机 IV 下两次加密输出必须不同")

	// 前缀即 IV：截取后按显式 IV 解密
	iv := c1[:ivSize]
	ct := c1[ivSize:]
	pt2, err := crypto.Decrypt(crypto.AES128, crypto.CBC, ct, crypto.WithKey(key), crypto.WithIV(iv))
	require.NoError(t, err)
	assert.Equal(t, pt, pt2)
}

func TestWithIV_NoPrefix(t *testing.T) {
	key := make([]byte, 16)
	pt := []byte("explicit iv no prefix") // 21B
	iv := bytes.Repeat([]byte{0xAB}, 16)

	ct, err := crypto.Encrypt(crypto.AES128, crypto.CBC, pt, crypto.WithKey(key), crypto.WithIV(iv))
	require.NoError(t, err)
	padLen := 16 - len(pt)%16
	assert.Equal(t, len(pt)+padLen, len(ct), "显式 IV 密文不应含 IV 前缀")

	// 不传 IV 走随机前缀路径：CBC 无认证，可能报错或静默解出错误明文
	// （本用例明文尾部+填充恰构成合法 PKCS7 结构，解密"成功"但明文错误），
	// 二者均证明"解密须对称传入同一 WithIV"才能拿回原明文。
	ptWrong, err := crypto.Decrypt(crypto.AES128, crypto.CBC, ct, crypto.WithKey(key))
	if err == nil {
		assert.NotEqual(t, pt, ptWrong, "不传 WithIV 不得解出原明文")
	}

	// 对称传 IV 可解
	pt2, err := crypto.Decrypt(crypto.AES128, crypto.CBC, ct, crypto.WithKey(key), crypto.WithIV(iv))
	require.NoError(t, err)
	assert.Equal(t, pt, pt2)
}

// ==================== nonce：显式 / 长度 / 模式限制 ====================

func TestWithNonce(t *testing.T) {
	key := make([]byte, 16)
	pt := []byte("explicit nonce") // 14B
	nonce := bytes.Repeat([]byte{0x42}, 12)

	ct, err := crypto.Encrypt(crypto.AES128, crypto.GCM, pt, crypto.WithKey(key), crypto.WithNonce(nonce))
	require.NoError(t, err)
	assert.Equal(t, len(pt)+16, len(ct), "GCM 显式 nonce 无前缀，仅含密文+tag")
	assert.False(t, bytes.HasPrefix(ct, nonce), "输出不应包含 nonce 前缀")

	// 解密须对称传同一 nonce
	pt2, err := crypto.Decrypt(crypto.AES128, crypto.GCM, ct, crypto.WithKey(key), crypto.WithNonce(nonce))
	require.NoError(t, err)
	assert.Equal(t, pt, pt2)

	// 不传 nonce（走嵌入前缀路径）→ 认证失败
	_, err = crypto.Decrypt(crypto.AES128, crypto.GCM, ct, crypto.WithKey(key))
	assert.Error(t, err)

	// 长度非 12 → ErrInvalidNonceLength
	_, err = crypto.Encrypt(crypto.AES128, crypto.GCM, pt, crypto.WithKey(key), crypto.WithNonce(make([]byte, 11)))
	assert.ErrorIs(t, err, crypto.ErrInvalidNonceLength)
	_, err = crypto.Encrypt(crypto.AES128, crypto.GCM, pt, crypto.WithKey(key), crypto.WithNonce(make([]byte, 13)))
	assert.ErrorIs(t, err, crypto.ErrInvalidNonceLength)

	// 非 GCM 传 nonce → ErrNonceNotSupported
	_, err = crypto.Encrypt(crypto.AES128, crypto.CBC, pt, crypto.WithKey(key), crypto.WithNonce(nonce))
	assert.ErrorIs(t, err, crypto.ErrNonceNotSupported)
	_, err = crypto.Encrypt(crypto.AES128, crypto.CTR, pt, crypto.WithKey(key), crypto.WithNonce(nonce))
	assert.ErrorIs(t, err, crypto.ErrNonceNotSupported)
}

// ==================== 错误统一：GCM 认证失败 / CBC 填充失败 ====================

func TestDecrypt_ErrorUniformity(t *testing.T) {
	key := make([]byte, 16)
	pt := []byte("uniform error check message payload") // 35B

	ct, err := crypto.Encrypt(crypto.AES128, crypto.GCM, pt, crypto.WithKey(key))
	require.NoError(t, err)
	assert.Equal(t, len(pt)+28, len(ct))

	// 篡改 nonce（前 12B）→ ErrAuthenticationFailed
	tampered := append([]byte(nil), ct...)
	tampered[0] ^= 0xFF
	_, err = crypto.Decrypt(crypto.AES128, crypto.GCM, tampered, crypto.WithKey(key))
	assert.ErrorIs(t, err, crypto.ErrAuthenticationFailed, "nonce 篡改")

	// 篡改密文（中间字节）→ ErrAuthenticationFailed
	tampered = append([]byte(nil), ct...)
	tampered[20] ^= 0xFF
	_, err = crypto.Decrypt(crypto.AES128, crypto.GCM, tampered, crypto.WithKey(key))
	assert.ErrorIs(t, err, crypto.ErrAuthenticationFailed, "密文篡改")

	// 篡改 tag（末 16B）→ ErrAuthenticationFailed
	tampered = append([]byte(nil), ct...)
	tampered[len(tampered)-1] ^= 0xFF
	_, err = crypto.Decrypt(crypto.AES128, crypto.GCM, tampered, crypto.WithKey(key))
	assert.ErrorIs(t, err, crypto.ErrAuthenticationFailed, "tag 篡改")

	// CBC 篡改 padding 区（改 C3 倒数第 2 字节，末字节保持 13 使校验必然失败）
	// → ErrInvalidPadding
	ct, err = crypto.Encrypt(crypto.AES128, crypto.CBC, pt, crypto.WithKey(key))
	require.NoError(t, err)
	tampered = append([]byte(nil), ct...)
	tampered[len(tampered)-2] ^= 0xFF
	_, err = crypto.Decrypt(crypto.AES128, crypto.CBC, tampered, crypto.WithKey(key))
	assert.ErrorIs(t, err, crypto.ErrInvalidPadding, "CBC padding 区篡改")
}

// ==================== 遗留算法：DES / TripleDES ====================

func TestDES_CBC_RoundTrip(t *testing.T) {
	key := []byte("01234567") // 8B
	pt := []byte("legacy DES CBC payload")

	ct, err := crypto.Encrypt(crypto.DES, crypto.CBC, pt, crypto.WithKey(key), crypto.WithInsecureAlgorithms())
	require.NoError(t, err)
	pt2, err := crypto.Decrypt(crypto.DES, crypto.CBC, ct, crypto.WithKey(key), crypto.WithInsecureAlgorithms())
	require.NoError(t, err)
	assert.Equal(t, pt, pt2)
}

func TestTripleDES_ECB(t *testing.T) {
	key := []byte("0123456789abcdef01234567") // 24B
	pt := []byte("legacy 3DES ECB payload")

	ct, err := crypto.Encrypt(crypto.TripleDES, crypto.ECB, pt, crypto.WithKey(key), crypto.WithInsecureAlgorithms())
	require.NoError(t, err)
	pt2, err := crypto.Decrypt(crypto.TripleDES, crypto.ECB, ct, crypto.WithKey(key), crypto.WithInsecureAlgorithms())
	require.NoError(t, err)
	assert.Equal(t, pt, pt2)
}

// ==================== 警示：无认证模式篡改静默成功 ====================

func TestUnauthenticated_Tamper_Silent(t *testing.T) {
	key := make([]byte, 16)
	pt := []byte("tamper silent check payload with enough length") // 46B

	// CTR：篡改密文字节 → 解密"成功"且明文已变（无认证不检测篡改）
	ct, err := crypto.Encrypt(crypto.AES128, crypto.CTR, pt, crypto.WithKey(key))
	require.NoError(t, err)
	tampered := append([]byte(nil), ct...)
	tampered[len(tampered)/2] ^= 0xFF
	pt2, err := crypto.Decrypt(crypto.AES128, crypto.CTR, tampered, crypto.WithKey(key))
	require.NoError(t, err, "CTR 篡改后解密必须无错误（无认证）")
	assert.NotEqual(t, pt, pt2, "CTR 篡改必须静默改变明文")

	// CBC：篡改第 1 密文块字节（不影响末块 padding 校验区）
	// → 解密"成功"且明文已变
	ct, err = crypto.Encrypt(crypto.AES128, crypto.CBC, pt, crypto.WithKey(key))
	require.NoError(t, err)
	tampered = append([]byte(nil), ct...)
	tampered[20] ^= 0xFF // C1 内字节：影响 P1/P2，不影响末块 padding
	pt2, err = crypto.Decrypt(crypto.AES128, crypto.CBC, tampered, crypto.WithKey(key))
	require.NoError(t, err, "CBC 篡改（非 padding 区）后解密必须无错误")
	assert.NotEqual(t, pt, pt2, "CBC 篡改必须静默改变明文")
}

// ==================== 并发安全（-race） ====================

func TestEncryptDecrypt_Concurrent(t *testing.T) {
	modes := []crypto.Mode{crypto.GCM, crypto.CBC, crypto.ECB, crypto.CFB, crypto.OFB, crypto.CTR}
	key := make([]byte, 16)
	pt := []byte("concurrent encrypt decrypt race check")

	var wg sync.WaitGroup
	for _, mode := range modes {
		wg.Add(1)
		go func(m crypto.Mode) {
			defer wg.Done()
			for range 50 {
				opts := []crypto.Option{crypto.WithKey(key)}
				if m == crypto.ECB {
					opts = append(opts, crypto.WithInsecureAlgorithms())
				}
				ct, err := crypto.Encrypt(crypto.AES128, m, pt, opts...)
				assert.NoError(t, err, "mode %s encrypt", m)
				if err != nil {
					continue
				}
				got, err := crypto.Decrypt(crypto.AES128, m, ct, opts...)
				assert.NoError(t, err, "mode %s decrypt", m)
				assert.Equal(t, pt, got, "mode %s 往返", m)
			}
		}(mode)
	}
	wg.Wait()
}

// ==================== 模式化 API 输入不变性（P3 修复） ====================

func TestEncryptDecrypt_InputImmutable(t *testing.T) {
	key := []byte("0123456789abcdef")
	data := []byte("input immutability via mode API")
	iv := []byte("abcdef0123456789")
	nonce := []byte("0123456789ab")

	cases := []struct {
		name string
		alg  crypto.Algorithm
		mode crypto.Mode
		opts []crypto.Option
	}{
		{"CBC default", crypto.AES128, crypto.CBC, nil},
		{"CBC WithIV", crypto.AES128, crypto.CBC, []crypto.Option{crypto.WithIV(iv)}},
		{"ECB", crypto.AES128, crypto.ECB, []crypto.Option{crypto.WithInsecureAlgorithms()}},
		{"CFB default", crypto.AES128, crypto.CFB, nil},
		{"CFB WithIV", crypto.AES128, crypto.CFB, []crypto.Option{crypto.WithIV(iv)}},
		{"OFB default", crypto.AES128, crypto.OFB, nil},
		{"OFB WithIV", crypto.AES128, crypto.OFB, []crypto.Option{crypto.WithIV(iv)}},
		{"CTR default", crypto.AES128, crypto.CTR, nil},
		{"CTR WithIV", crypto.AES128, crypto.CTR, []crypto.Option{crypto.WithIV(iv)}},
		{"GCM default", crypto.AES128, crypto.GCM, nil},
		{"GCM WithNonce", crypto.AES128, crypto.GCM, []crypto.Option{crypto.WithNonce(nonce)}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := append([]crypto.Option{crypto.WithKey(key)}, tc.opts...)

			// 加密：data 输入不变
			origData := append([]byte(nil), data...)
			ciphertext, err := crypto.Encrypt(tc.alg, tc.mode, data, opts...)
			require.NoError(t, err)
			require.Equal(t, origData, data, "%s Encrypt 不应修改 data 输入", tc.name)

			// 解密：ciphertext 输入不变
			origCT := append([]byte(nil), ciphertext...)
			dec, err := crypto.Decrypt(tc.alg, tc.mode, ciphertext, opts...)
			require.NoError(t, err)
			require.Equal(t, origCT, ciphertext, "%s Decrypt 不应修改 ciphertext 输入", tc.name)
			assert.Equal(t, data, dec, "%s 往返结果", tc.name)
		})
	}
}

// ==================== 审核修复：GCM 过短密文与认证失败区分（P5） ====================

func TestDecryptGCM_TooShort_Distinct(t *testing.T) {
	key := make([]byte, 16)

	// 密文 < 12B（无法容纳嵌入 nonce）→ ErrCiphertextTooShort
	for _, n := range []int{0, 1, 11} {
		_, err := crypto.Decrypt(crypto.AES128, crypto.GCM, make([]byte, n), crypto.WithKey(key))
		assert.ErrorIs(t, err, crypto.ErrCiphertextTooShort, "%dB 密文", n)
	}

	// 12~27B（nonce 可容纳但认证必然失败）→ ErrAuthenticationFailed
	for _, n := range []int{12, 20, 27} {
		_, err := crypto.Decrypt(crypto.AES128, crypto.GCM, make([]byte, n), crypto.WithKey(key))
		assert.ErrorIs(t, err, crypto.ErrAuthenticationFailed, "%dB 密文", n)
	}
}

// ==================== 审核修复：长度类错误哨兵导出（P6） ====================

func TestCiphertextLength_Sentinels(t *testing.T) {
	key := make([]byte, 16)

	// CTR 默认路径：3B 密文（不足计数器 16B）→ ErrCiphertextTooShort
	_, err := crypto.Decrypt(crypto.AES128, crypto.CTR, make([]byte, 3), crypto.WithKey(key))
	assert.ErrorIs(t, err, crypto.ErrCiphertextTooShort)

	// CBC 默认路径：17B 密文（取 16B IV 后余 1B 非整块）→ ErrCiphertextNotAligned
	_, err = crypto.Decrypt(crypto.AES128, crypto.CBC, make([]byte, 17), crypto.WithKey(key))
	assert.ErrorIs(t, err, crypto.ErrCiphertextNotAligned)

	// CBC 显式 IV 路径：非整块密文 → ErrCiphertextNotAligned
	_, err = crypto.Decrypt(crypto.AES128, crypto.CBC, make([]byte, 17), crypto.WithKey(key), crypto.WithIV(make([]byte, 16)))
	assert.ErrorIs(t, err, crypto.ErrCiphertextNotAligned)

	// CFB/OFB 默认路径：不足前缀 → ErrCiphertextTooShort
	_, err = crypto.Decrypt(crypto.AES128, crypto.CFB, make([]byte, 3), crypto.WithKey(key))
	assert.ErrorIs(t, err, crypto.ErrCiphertextTooShort)
	_, err = crypto.Decrypt(crypto.AES128, crypto.OFB, make([]byte, 3), crypto.WithKey(key))
	assert.ErrorIs(t, err, crypto.ErrCiphertextTooShort)

	// ECB 默认路径：非整块密文 → ErrCiphertextNotAligned
	_, err = crypto.Decrypt(crypto.AES128, crypto.ECB, make([]byte, 17), crypto.WithKey(key), crypto.WithInsecureAlgorithms())
	assert.ErrorIs(t, err, crypto.ErrCiphertextNotAligned)
}
