package envelope

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rootcrypto "github.com/charlienet/go-crypto"
)

// ==================== gcx1 往返测试 ====================

func TestGCX1_RoundTrip_SM4(t *testing.T) {
	key := []byte("0123456789abcdef") // SM4: 16 bytes
	plaintext := []byte("hello, sm4!")

	envelope, err := Encrypt(rootcrypto.SM4, key, plaintext)
	assert.NoError(t, err)
	assert.True(t, bytes.HasPrefix(envelope, []byte(gcx1Magic)))

	decrypted, err := Decrypt(key, envelope)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestGCX1_RoundTrip_AES128(t *testing.T) {
	key := []byte("0123456789abcdef") // AES-128: 16 bytes
	plaintext := []byte("hello, aes128!")

	envelope, err := Encrypt(rootcrypto.AES128, key, plaintext)
	assert.NoError(t, err)

	decrypted, err := Decrypt(key, envelope)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestGCX1_RoundTrip_AES192(t *testing.T) {
	key := []byte("0123456789abcdef01234567") // AES-192: 24 bytes
	plaintext := []byte("hello, aes192!")

	envelope, err := Encrypt(rootcrypto.AES192, key, plaintext)
	assert.NoError(t, err)

	decrypted, err := Decrypt(key, envelope)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestGCX1_RoundTrip_AES256(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef") // AES-256: 32 bytes
	plaintext := []byte("hello, aes256!")

	envelope, err := Encrypt(rootcrypto.AES256, key, plaintext)
	assert.NoError(t, err)

	decrypted, err := Decrypt(key, envelope)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

// ==================== gcx1 信封结构验证 ====================

func TestGCX1_Structure(t *testing.T) {
	key := []byte("0123456789abcdef")
	plaintext := []byte("test")

	envelope, err := Encrypt(rootcrypto.AES128, key, plaintext)
	assert.NoError(t, err)

	// 验证总长度：header(7) + nonce(12) + ciphertext(4) + tag(16) = 39
	assert.Equal(t, gcx1HeaderLen+gcx1NonceLen+len(plaintext)+gcx1TagLen, len(envelope))

	// 验证 header
	assert.Equal(t, byte('g'), envelope[0])
	assert.Equal(t, byte('c'), envelope[1])
	assert.Equal(t, byte('x'), envelope[2])
	assert.Equal(t, byte('1'), envelope[3])
	assert.Equal(t, byte(gcx1VersionV2), envelope[4], "新加密输出应为 v2 版本")
	assert.Equal(t, algIDAES128, envelope[5])
	assert.Equal(t, byte(gcx1NonceLen), envelope[6])
}

// ==================== v1 兼容读取（gcx1 v2 演进） ====================

func TestGCX1_V1Compatibility(t *testing.T) {
	key := []byte("0123456789abcdef")
	plaintext := []byte("legacy v1 data")

	// 手工构造 v1 信封：GCM 无 AAD（v1 冻结格式）
	c, err := rootcrypto.NewCipher("AES-128", key)
	require.NoError(t, err)
	gcm, err := c.NewGCMWithRandomNonce() // embednonce=true，输出 nonce||ct||tag
	require.NoError(t, err)
	sealed, err := gcm.Encrypt(plaintext)
	require.NoError(t, err)

	envelope := make([]byte, 0, gcx1HeaderLen+len(sealed))
	envelope = append(envelope, gcx1Magic...)
	envelope = append(envelope, gcx1Version) // v1 版本号
	envelope = append(envelope, algIDAES128)
	envelope = append(envelope, gcx1NonceLen)
	envelope = append(envelope, sealed...)

	decrypted, err := Decrypt(key, envelope)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

// TestGCX1_V1Compatibility_WithAAD 验证 v1 信封 + 用户 AAD 的兼容语义：
// v1 冻结格式无 header meta AAD，但用户 AAD（若有）始终参与 GCM 认证。
func TestGCX1_V1Compatibility_WithAAD(t *testing.T) {
	key := []byte("0123456789abcdef")
	plaintext := []byte("legacy v1 data with aad")
	userAAD := []byte("user-context-aad")

	// 手工构造 v1 信封：GCM AAD = 用户 AAD（v1 无 header meta AAD）
	c, err := rootcrypto.NewCipher("AES-128", key)
	require.NoError(t, err)
	gcm, err := c.NewGCM(nil, rootcrypto.WithAAD(userAAD), rootcrypto.EmbedNonce()) // embednonce=true，输出 nonce||ct||tag
	require.NoError(t, err)
	sealed, err := gcm.Encrypt(plaintext)
	require.NoError(t, err)

	envelope := make([]byte, 0, gcx1HeaderLen+len(sealed))
	envelope = append(envelope, gcx1Magic...)
	envelope = append(envelope, gcx1Version) // v1 版本号
	envelope = append(envelope, algIDAES128)
	envelope = append(envelope, gcx1NonceLen)
	envelope = append(envelope, sealed...)

	// 正向：v1 信封 + 相同用户 AAD → DecryptWithAAD 往返成功
	decrypted, err := DecryptWithAAD(key, envelope, userAAD)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)

	// 负向：v1 信封（带用户 AAD 加密）按"无 AAD 的 v2 语义"解密必须失败——
	// 将 version 篡改为 v2 后走 v2 分支（GCM AAD = header meta），
	// 与加密时的 GCM AAD（= 用户 AAD）不一致，GCM 认证必须拒绝。
	downgraded := make([]byte, len(envelope))
	copy(downgraded, envelope)
	downgraded[4] = byte(gcx1VersionV2)
	_, err = Decrypt(key, downgraded)
	assert.Error(t, err, "v1+用户AAD 密文按无 AAD 的 v2 语义解密必须失败")

	// 负向补充：保持 v1 版本但用无 AAD 的 Decrypt（v1 分支 GCM AAD = nil）同样必须失败
	_, err = Decrypt(key, envelope)
	assert.Error(t, err, "v1+用户AAD 密文按无 AAD 的 v1 语义解密必须失败")
}

// ==================== v2 header 篡改防护（header 入 GCM AAD） ====================

func TestGCX1_V2_HeaderTamper(t *testing.T) {
	key := []byte("0123456789abcdef")
	envelope, err := Encrypt(rootcrypto.AES128, key, []byte("test"))
	require.NoError(t, err)
	assert.Equal(t, byte(gcx1VersionV2), envelope[4])

	// 篡改 header 各元数据字节：v2 下必须解密失败（前置校验或 GCM 认证拒绝）
	cases := []struct {
		name string
		idx  int
		val  byte
	}{
		{"magic", 0, 'X'},
		{"version", 4, 0x03},
		{"algID", 5, algIDSM4}, // 篡改为合法算法 ID：由 GCM AAD 认证拒绝
		{"nonceLen", 6, 0x08},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tampered := make([]byte, len(envelope))
			copy(tampered, envelope)
			tampered[tc.idx] = tc.val
			_, err := Decrypt(key, tampered)
			assert.Error(t, err, "篡改 %s 应解密失败", tc.name)
		})
	}

	// 篡改 algID 为未知值：errGcx1UnknownAlgID（前置校验拦截）
	unknown := make([]byte, len(envelope))
	copy(unknown, envelope)
	unknown[5] = 0xFF
	_, err = Decrypt(key, unknown)
	assert.ErrorIs(t, err, errGcx1UnknownAlgID)
}

// ==================== 空明文往返 ====================

func TestGCX1_EmptyPlaintext(t *testing.T) {
	key := []byte("0123456789abcdef")

	envelope, err := Encrypt(rootcrypto.AES128, key, []byte{})
	assert.NoError(t, err)

	decrypted, err := Decrypt(key, envelope)
	assert.NoError(t, err)
	assert.Empty(t, decrypted)
}

// ==================== NonceLen 不匹配 ====================

func TestGCX1_Tamper_NonceLen(t *testing.T) {
	key := []byte("0123456789abcdef")
	envelope, _ := Encrypt(rootcrypto.AES128, key, []byte("test"))

	tampered := make([]byte, len(envelope))
	copy(tampered, envelope)
	tampered[6] = 0x08 // 错误的 nonceLen（应为 12）

	_, err := Decrypt(key, tampered)
	assert.ErrorIs(t, err, errGcx1NonceLenMismatch)
}



// ==================== EncryptWithAAD DES 拒绝 ====================

func TestGCX1_EncryptWithAAD_DES_Rejected(t *testing.T) {
	key := []byte("01234567")
	_, err := EncryptWithAAD(rootcrypto.DES, key, []byte("test"), []byte("aad"))
	assert.ErrorIs(t, err, errGcx1DESNotSupported)
}

// ==================== 篡改测试 ====================

func TestGCX1_Tamper_Magic(t *testing.T) {
	key := []byte("0123456789abcdef")
	envelope, _ := Encrypt(rootcrypto.AES128, key, []byte("test"))

	// 篡改魔数
	tampered := make([]byte, len(envelope))
	copy(tampered, envelope)
	tampered[0] = 'X'

	_, err := Decrypt(key, tampered)
	assert.ErrorIs(t, err, errGcx1MagicMismatch)
}

func TestGCX1_Tamper_Version(t *testing.T) {
	key := []byte("0123456789abcdef")
	envelope, _ := Encrypt(rootcrypto.AES128, key, []byte("test"))
	// 新加密输出为 v2
	assert.Equal(t, byte(gcx1VersionV2), envelope[4])

	// v2 密文：篡改 version 为未知值（0x03）→ 版本检查拒绝
	tampered := make([]byte, len(envelope))
	copy(tampered, envelope)
	tampered[4] = 0x03 // 未知版本
	_, err := Decrypt(key, tampered)
	assert.ErrorIs(t, err, errGcx1VersionMismatch)

	// v2 密文：降级篡改为 v1 → 走 v1 路径（AAD=nil）→ GCM 认证失败
	tampered[4] = byte(gcx1Version)
	_, err = Decrypt(key, tampered)
	assert.Error(t, err, "降级篡改 version 应导致 GCM 认证失败")
}

func TestGCX1_Tamper_AlgID(t *testing.T) {
	key := []byte("0123456789abcdef")
	envelope, _ := Encrypt(rootcrypto.AES128, key, []byte("test"))

	tampered := make([]byte, len(envelope))
	copy(tampered, envelope)
	tampered[5] = 0xFF // 未知 algID

	_, err := Decrypt(key, tampered)
	assert.ErrorIs(t, err, errGcx1UnknownAlgID)
}

func TestGCX1_Tamper_Nonce(t *testing.T) {
	key := []byte("0123456789abcdef")
	envelope, _ := Encrypt(rootcrypto.AES128, key, []byte("test"))

	tampered := make([]byte, len(envelope))
	copy(tampered, envelope)
	tampered[7] ^= 0xFF // 篡改 nonce 首字节

	_, err := Decrypt(key, tampered)
	assert.Error(t, err) // GCM Open 失败
}

func TestGCX1_Tamper_Ciphertext(t *testing.T) {
	key := []byte("0123456789abcdef")
	envelope, _ := Encrypt(rootcrypto.AES128, key, []byte("test"))

	tampered := make([]byte, len(envelope))
	copy(tampered, envelope)
	tampered[len(tampered)-3] ^= 0xFF // 篡改密文

	_, err := Decrypt(key, tampered)
	assert.Error(t, err) // GCM Open 失败
}

func TestGCX1_Tamper_Tag(t *testing.T) {
	key := []byte("0123456789abcdef")
	envelope, _ := Encrypt(rootcrypto.AES128, key, []byte("test"))

	tampered := make([]byte, len(envelope))
	copy(tampered, envelope)
	tampered[len(tampered)-1] ^= 0xFF // 篡改 tag 末字节

	_, err := Decrypt(key, tampered)
	assert.Error(t, err) // GCM Open 失败
}

// ==================== AAD 不一致拒绝 ====================

func TestGCX1_AAD_Inconsistent(t *testing.T) {
	key := []byte("0123456789abcdef")
	plaintext := []byte("test aad")
	aad1 := []byte("aad-v1")
	aad2 := []byte("aad-v2")

	envelope, err := EncryptWithAAD(rootcrypto.AES128, key, plaintext, aad1)
	assert.NoError(t, err)

	// 使用不同 AAD 解密，应失败
	_, err = DecryptWithAAD(key, envelope, aad2)
	assert.Error(t, err)
}

func TestGCX1_AAD_Consistent(t *testing.T) {
	key := []byte("0123456789abcdef")
	plaintext := []byte("test aad")
	aad := []byte("consistent-aad")

	envelope, err := EncryptWithAAD(rootcrypto.AES128, key, plaintext, aad)
	assert.NoError(t, err)

	decrypted, err := DecryptWithAAD(key, envelope, aad)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestGCX1_AAD_EncryptWithout_DecryptWith(t *testing.T) {
	key := []byte("0123456789abcdef")
	plaintext := []byte("test")

	// 不使用 AAD 加密
	envelope, err := Encrypt(rootcrypto.AES128, key, plaintext)
	assert.NoError(t, err)

	// 尝试用 AAD 解密，应失败
	_, err = DecryptWithAAD(key, envelope, []byte("extra-aad"))
	assert.Error(t, err)
}

// ==================== 未知算法拒绝 ====================



// ==================== DES/3DES 拒绝 ====================

func TestGCX1_DES_Rejected(t *testing.T) {
	key := []byte("01234567") // DES: 8 bytes

	_, err := Encrypt(rootcrypto.DES, key, []byte("test"))
	assert.ErrorIs(t, err, errGcx1DESNotSupported)
}

func TestGCX1_3DES_Rejected(t *testing.T) {
	key := []byte("0123456789abcdef01234567") // 3DES: 24 bytes

	_, err := Encrypt(rootcrypto.TripleDES, key, []byte("test"))
	assert.ErrorIs(t, err, errGcx1DESNotSupported)
}

func TestGCX1_DES_AlgoIDRejected(t *testing.T) {
	// 构造一个含有 DES algID 的伪造信封
	key := []byte("01234567")
	fake := make([]byte, 19)
	copy(fake, gcx1Magic)
	fake[4] = gcx1Version
	fake[5] = algIDDES // DES
	fake[6] = gcx1NonceLen

	_, err := Decrypt(key, fake)
	assert.ErrorIs(t, err, errGcx1DESNotSupported)
}

func TestGCX1_3DES_AlgoIDRejected(t *testing.T) {
	key := []byte("0123456789abcdef01234567")
	fake := make([]byte, 19)
	copy(fake, gcx1Magic)
	fake[4] = gcx1Version
	fake[5] = algID3DES
	fake[6] = gcx1NonceLen

	_, err := Decrypt(key, fake)
	assert.ErrorIs(t, err, errGcx1DESNotSupported)
}

// ==================== 长度不足拒绝 ====================

func TestGCX1_TooShort(t *testing.T) {
	key := []byte("0123456789abcdef")

	_, err := Decrypt(key, []byte("short"))
	assert.ErrorIs(t, err, errGcx1TooShort)
}



// ==================== 并发测试 ====================

func TestGCX1_Concurrent(t *testing.T) {
	key := []byte("0123456789abcdef")
	plaintext := []byte("concurrent test data")

	var wg sync.WaitGroup
	errs := make(chan error, 20)

	for i := 0; i < 10; i++ {
		wg.Add(2)

		// 并发加密
		go func() {
			defer wg.Done()
			_, err := Encrypt(rootcrypto.AES128, key, plaintext)
			errs <- err
		}()

		// 并发加密（带 AAD）
		go func() {
			defer wg.Done()
			_, err := EncryptWithAAD(rootcrypto.SM4, key, plaintext, []byte("aad"))
			errs <- err
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		assert.NoError(t, err)
	}
}

func TestGCX1_Concurrent_RoundTrip(t *testing.T) {
	key := []byte("0123456789abcdef")
	plaintext := []byte("round trip concurrent")

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

	envelope, err := Encrypt(rootcrypto.AES128, key, plaintext)
			if err != nil {
				t.Errorf("Encrypt failed: %v", err)
				return
			}

			decrypted, err := Decrypt(key, envelope)
			if err != nil {
				t.Errorf("Decrypt failed: %v", err)
				return
			}
			if !bytes.Equal(plaintext, decrypted) {
				t.Errorf("round trip mismatch: got %s, want %s", decrypted, plaintext)
			}
		}()
	}
	wg.Wait()
}

// ==================== 多算法同密钥加密（确保 nonce 随机性） ====================

func TestGCX1_NonceRandomness(t *testing.T) {
	key := []byte("0123456789abcdef")
	plaintext := []byte("same plaintext")

	// 同一明文加密两次，信封应不同（因为 nonce 随机）
	env1, err := Encrypt(rootcrypto.AES128, key, plaintext)
	assert.NoError(t, err)
	env2, err := Encrypt(rootcrypto.AES128, key, plaintext)
	assert.NoError(t, err)

	// 信封内容应不同（nonce 不同导致密文不同）
	assert.False(t, bytes.Equal(env1, env2), "两次加密应产生不同信封")

	// 但都能正确解密
	d1, err := Decrypt(key, env1)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, d1)
	d2, err := Decrypt(key, env2)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, d2)
}

// ==================== 错误密钥解密 ====================

func TestGCX1_WrongKey(t *testing.T) {
	key1 := []byte("0123456789abcdef")
	key2 := []byte("fedcba9876543210")
	plaintext := []byte("secret")

	envelope, err := Encrypt(rootcrypto.AES128, key1, plaintext)
	assert.NoError(t, err)

	_, err = Decrypt(key2, envelope)
	assert.Error(t, err) // GCM 认证失败
}

// ==================== 大数据量测试 ====================

func TestGCX1_LargePlaintext(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef") // AES-256: 32 bytes
	plaintext := make([]byte, 1024*1024)              // 1MB
	_, err := io.ReadFull(rand.Reader, plaintext)
	assert.NoError(t, err)

	envelope, err := Encrypt(rootcrypto.AES256, key, plaintext)
	assert.NoError(t, err)

	decrypted, err := Decrypt(key, envelope)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

// ==================== 冻结格式黄金向量（KAT） ====================
// KAT（Known Answer Test）以固定 key/明文/布局手工构造密文字节并固化为
// 字面量常量，独立锚定 gcx1 v1/v2 冻结格式。与"用当前库现造"的白盒测试
// 互为反证：白盒构造与实现同源，格式漂移会同步漂移；KAT 不依赖运行时生成，
// 实现或测试任何一处改动格式（header 布局、版本字节、nonce 位置、AAD 语义、
// 密文/tag 长度），KAT 断言即失败。
//
// 生成方法（一次性，随本测试固化，非运行时生成）：
//   - key = "0123456789abcdef"（AES-128）、明文 = "hello, gcx1 kat!"、
//     nonce = 全零 12B、algID = 0x02（AES-128）。
//   - v1：GCM 无 AAD 加密，信封 = magic(4) || 0x01 || 0x02 || 0x0C ||
//     nonce(12B) || 密文(16B) || tag(16B)。
//   - v2：GCM AAD = header 元数据 7 字节（magic||0x02||0x02||0x0C），
//     其余布局同 v1。v1/v2 密文区相同（CTR 密文与 AAD 无关），仅 tag 不同，
//     直观体现"AAD 只认证不加密"。
const (
	gcx1KATKey   = "0123456789abcdef"
	gcx1KATPlain = "hello, gcx1 kat!"
	gcx1KATNonce = "000000000000000000000000"
	// gcx1 v1 KAT 密文：67637831 0102 0c | 00×12 | 2a87...4ca3(16B) | 79f5...1407(16B)
	gcx1KATV1Hex = "6763783101020c000000000000000000000000" +
		"2a87462996a6aca4ec2ea090cecd4ca3" +
		"79f59da024f00da6ddd6a932424e1407"
	// gcx1 v2 KAT 密文：同上布局，version=0x02，tag 不同（AAD=header meta 7B）
	gcx1KATV2Hex = "6763783102020c000000000000000000000000" +
		"2a87462996a6aca4ec2ea090cecd4ca3" +
		"a58c5e8be0017aa0e772c4372a4ed928"
)

// gcx1KATDecrypt 将 KAT hex 常量解码并解密，返回明文与信封字节。
func gcx1KATDecrypt(t *testing.T, hexStr string) ([]byte, []byte) {
	t.Helper()
	env, err := hex.DecodeString(hexStr)
	require.NoError(t, err, "KAT hex 常量必须可解码")
	pt, err := Decrypt([]byte(gcx1KATKey), env)
	require.NoError(t, err, "KAT 密文必须能被当前实现解密")
	return pt, env
}

func TestGCX1_KAT_V1(t *testing.T) {
	pt, env := gcx1KATDecrypt(t, gcx1KATV1Hex)
	assert.Equal(t, []byte(gcx1KATPlain), pt)
	// 布局锚定：v1 版本字节、nonce 区与常量一致、total 长度（7+12+16+16=51）
	assert.Equal(t, byte(gcx1Version), env[4])
	assert.Equal(t, gcx1KATNonce, hex.EncodeToString(env[gcx1HeaderLen:gcx1HeaderLen+gcx1NonceLen]))
	assert.Equal(t, len(env), gcx1HeaderLen+gcx1NonceLen+len(pt)+gcx1TagLen)
}

func TestGCX1_KAT_V2(t *testing.T) {
	pt, env := gcx1KATDecrypt(t, gcx1KATV2Hex)
	assert.Equal(t, []byte(gcx1KATPlain), pt)
	assert.Equal(t, byte(gcx1VersionV2), env[4])
	assert.Equal(t, gcx1KATNonce, hex.EncodeToString(env[gcx1HeaderLen:gcx1HeaderLen+gcx1NonceLen]))
	assert.Equal(t, len(env), gcx1HeaderLen+gcx1NonceLen+len(pt)+gcx1TagLen)
}

// TestGCX1_KAT_TamperAnyByte 篡改 KAT 密文任一字节，解密必须失败：
// header 字节被前置校验（magic/version/algID/nonceLen）拒绝；
// nonce/密文/tag 字节被 GCM 认证拒绝；v1 降级 v2 / v2 降级 v1 因 AAD 语义
// 不同同样被 GCM 认证拒绝。
func TestGCX1_KAT_TamperAnyByte(t *testing.T) {
	cases := []struct {
		name   string
		hexStr string
	}{
		{"v1", gcx1KATV1Hex},
		{"v2", gcx1KATV2Hex},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env, err := hex.DecodeString(tc.hexStr)
			require.NoError(t, err)
			for i := range env {
				orig := env[i]
				env[i] = orig ^ 0xFF
				_, err := Decrypt([]byte(gcx1KATKey), env)
				assert.Error(t, err, "篡改字节 %d 应解密失败", i)
				env[i] = orig
			}
		})
	}
}
