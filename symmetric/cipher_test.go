package symmetric

import (
	"bytes"
	"io"
	"testing"

	"github.com/charlienet/go-crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==================== AES-GCM ====================

func TestSymmetric_AES_GCM(t *testing.T) {
	key := []byte("0123456789abcdef") // 16 bytes for AES-128
	plaintext := []byte("hello world")

	cipher, err := NewCipher("AES", key)
	assert.NoError(t, err)

	// 使用 GCM 模式，随机 nonce
	gcm, err := cipher.NewGCMWithRandomNonce()
	assert.NoError(t, err)

	// 加密
	encrypted, err := gcm.Encrypt(plaintext)
	assert.NoError(t, err)
	assert.NotEqual(t, plaintext, []byte(encrypted))

	// 解密
	decrypted, err := gcm.Decrypt(encrypted)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, []byte(decrypted))
}

// ==================== AES-CBC ====================

func TestSymmetric_AES_CBC(t *testing.T) {
	key := []byte("0123456789abcdef")
	iv := []byte("abcdef0123456789") // 16 bytes IV
	plaintext := []byte("hello world")

	cipher, err := NewCipher("AES", key)
	assert.NoError(t, err)

	// 使用 CBC 模式
	cbc, err := cipher.NewCBC(iv)
	assert.NoError(t, err)

	// 加密
	encrypted, err := cbc.Encrypt(plaintext)
	assert.NoError(t, err)
	assert.NotEqual(t, plaintext, []byte(encrypted))

	// 解密
	decrypted, err := cbc.Decrypt(encrypted)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, []byte(decrypted))
}

// ==================== AES-CTR ====================

func TestSymmetric_AES_CTR(t *testing.T) {
	key := []byte("0123456789abcdef")
	iv := []byte("abcdef0123456789")
	plaintext := []byte("hello world")

	cipher, err := NewCipher("AES", key)
	assert.NoError(t, err)

	// 使用 CTR 模式
	ctr, err := cipher.NewCTR(iv)
	assert.NoError(t, err)

	// 加密
	encrypted := ctr.XORKeyStream(plaintext)
	assert.NotEqual(t, plaintext, encrypted)

	// 重新创建 CTR（CTR 模式需要重新初始化才能解密）
	ctr2, err := cipher.NewCTR(iv)
	assert.NoError(t, err)
	decrypted := ctr2.XORKeyStream(encrypted)
	assert.Equal(t, plaintext, decrypted)
}

// ==================== SM4-GCM ====================

func TestSymmetric_SM4(t *testing.T) {
	key := []byte("0123456789abcdef") // 16 bytes for SM4
	plaintext := []byte("hello world")

	cipher, err := NewCipher("SM4", key)
	assert.NoError(t, err)

	// 使用 GCM 模式
	gcm, err := cipher.NewGCMWithRandomNonce()
	assert.NoError(t, err)

	// 加密
	encrypted, err := gcm.Encrypt(plaintext)
	assert.NoError(t, err)
	assert.NotEqual(t, plaintext, []byte(encrypted))

	// 解密
	decrypted, err := gcm.Decrypt(encrypted)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, []byte(decrypted))
}

// ==================== 错误路径 ====================

func TestSymmetric_InvalidAlgorithm(t *testing.T) {
	key := []byte("0123456789abcdef")

	_, err := NewCipher("INVALID", key)
	assert.Error(t, err)
}

func TestSymmetric_InvalidKeyLength(t *testing.T) {
	key := []byte("short") // 太短

	_, err := NewCipher("AES", key)
	assert.Error(t, err)
}

// ==================== 密钥生成 ====================

func TestGenerateKey(t *testing.T) {
	key, iv, nonce, err := crypto.GenerateKey("AES")
	assert.NoError(t, err)
	assert.Len(t, key, 16) // AES-128
	assert.Len(t, iv, 16)
	assert.Len(t, nonce, 12)
}

func TestGenerateKey_IndependentSlices(t *testing.T) {
	key, iv, nonce, err := crypto.GenerateKey("AES")
	require.NoError(t, err)

	// key/iv/nonce 独立分配，不共享底层数组：
	// 修改 key 不应影响 iv/nonce
	origIV := append([]byte(nil), iv...)
	origNonce := append([]byte(nil), nonce...)
	key[0] ^= 0xFF
	assert.Equal(t, origIV, iv, "修改 key 不应影响 iv")
	assert.Equal(t, origNonce, nonce, "修改 key 不应影响 nonce")

	// 修改 iv 不应影响 key/nonce
	origKey := append([]byte(nil), key...)
	iv[0] ^= 0xFF
	assert.Equal(t, origKey, key, "修改 iv 不应影响 key")
	assert.Equal(t, origNonce, nonce, "修改 iv 不应影响 nonce")
}

// ==================== PKCS7 填充 ====================

func TestPKCS7Padding(t *testing.T) {
	key := []byte("0123456789abcdef")
	cipher, err := NewCipher("AES", key)
	assert.NoError(t, err)

	sym := cipher.(*symmetric)
	block := sym.Block()

	// 测试填充
	data := []byte("hello")
	padding := crypto.PKCS7{}
	padded, err := padding.Padding(block.BlockSize(), data)
	assert.NoError(t, err)
	assert.Len(t, padded, 16) // 5 + 11 bytes padding

	// 测试去填充
	unpadded, err := padding.UnPadding(block.BlockSize(), padded)
	assert.NoError(t, err)
	assert.Equal(t, data, unpadded)

	// 测试边界情况：数据长度正好是块大小
	data = []byte("0123456789abcdef") // 16 bytes
	padded, err = padding.Padding(block.BlockSize(), data)
	assert.NoError(t, err)
	assert.Len(t, padded, 32) // 16 + 16 bytes padding

	unpadded, err = padding.UnPadding(block.BlockSize(), padded)
	assert.NoError(t, err)
	assert.Equal(t, data, unpadded)
}

// ==================== Padding 模式测试 ====================

func TestZeroPadding(t *testing.T) {
	padding := crypto.ZeroPadding{}

	blockSize := 16
	data := []byte("hello")
	padded, err := padding.Padding(blockSize, data)
	assert.NoError(t, err)
	assert.Len(t, padded, 16) // 5 + 11 bytes of zeros

	unpadded, err := padding.UnPadding(blockSize, padded)
	assert.NoError(t, err)
	assert.Equal(t, data, unpadded)

	// 测试数据长度正好是块大小的情况
	data = []byte("0123456789abcdef") // 16 bytes
	padded, err = padding.Padding(blockSize, data)
	assert.NoError(t, err)
	assert.Len(t, padded, 16) // 16 bytes, no padding needed

	unpadded, err = padding.UnPadding(blockSize, padded)
	assert.NoError(t, err)
	assert.Equal(t, data, unpadded)

	// 测试填充全零的情况
	data = []byte("test")
	padded, err = padding.Padding(blockSize, data)
	assert.NoError(t, err)
	assert.Len(t, padded, 16)
	// 检查后12个字节是否都是0
	for i := 4; i < 16; i++ {
		assert.Equal(t, byte(0), padded[i])
	}

	unpadded, err = padding.UnPadding(blockSize, padded)
	assert.NoError(t, err)
	assert.Equal(t, data, unpadded)
}

// TestZeroPadding_TrailingZeros 固化 ZeroPadding 的已知限制行为（文档警告方案）：
// UnPadding 无条件剥离尾部 0x00，因此以 0x00 结尾的二进制明文会在往返后静默损坏。
// 这是文档警告而非修复实现——二进制数据应改用 PKCS7 等自描述填充。
func TestZeroPadding_TrailingZeros(t *testing.T) {
	padding := crypto.ZeroPadding{}
	blockSize := 16

	data := []byte("data\x00\x00") // 7 字节，含尾部 0x00
	padded, err := padding.Padding(blockSize, data)
	assert.NoError(t, err)
	assert.Len(t, padded, 16) // 补齐 9 个 0x00 到整块

	unpadded, err := padding.UnPadding(blockSize, padded)
	assert.NoError(t, err)
	// 尾零被无条件剥离，明文 "data\x00\x00" 静默损坏为 "data"
	assert.Equal(t, []byte("data"), unpadded)
}

func TestNoPadding(t *testing.T) {
	padding := crypto.NoPadding{}

	blockSize := 16
	// 测试长度正确的数据
	data := []byte("0123456789abcdef") // 16 bytes
	padded, err := padding.Padding(blockSize, data)
	assert.NoError(t, err)
	assert.Equal(t, data, padded) // 应该没有变化

	unpadded, err := padding.UnPadding(blockSize, padded)
	assert.NoError(t, err)
	assert.Equal(t, data, unpadded)

	// 测试长度不正确的数据
	shortData := []byte("hello")
	_, err = padding.Padding(blockSize, shortData)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "data length must be multiple of block size")
}

func TestCBCWithZeroPadding(t *testing.T) {
	key := []byte("0123456789abcdef")
	iv := []byte("abcdef0123456789")
	plaintext := []byte("hello world") // 11 bytes, needs padding to 16

	cipher, err := NewCipher("AES", key)
	assert.NoError(t, err)

	// 使用 CBC 模式和 ZeroPadding
	cbc, err := cipher.NewCBC(iv, WithPadding(crypto.ZeroPadding{}))
	assert.NoError(t, err)

	// 加密
	encrypted, err := cbc.Encrypt(plaintext)
	assert.NoError(t, err)
	assert.NotEqual(t, plaintext, []byte(encrypted))

	// 解密
	decrypted, err := cbc.Decrypt(encrypted)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, []byte(decrypted))
}

func TestECBWithNoPadding(t *testing.T) {
	key := []byte("0123456789abcdef")
	plaintext := []byte("0123456789abcdef") // 16 bytes, exactly one block

	cipher, err := NewCipher("AES", key)
	assert.NoError(t, err)

	// 使用 ECB 模式和 NoPadding
	ecb, err := cipher.NewECB(WithPadding(crypto.NoPadding{}))
	assert.NoError(t, err)

	// 加密
	encrypted, err := ecb.Encrypt(plaintext)
	assert.NoError(t, err)
	assert.NotEqual(t, plaintext, []byte(encrypted))

	// 解密
	decrypted, err := ecb.Decrypt(encrypted)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, []byte(decrypted))

	// 尝试加密长度不对的数据，应该失败
	invalidPlaintext := []byte("hello")
	_, err = ecb.Encrypt(invalidPlaintext)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "data length must be multiple of block size")
}

func TestDefaultPKCS7Padding(t *testing.T) {
	key := []byte("0123456789abcdef")
	iv := []byte("abcdef0123456789")
	plaintext := []byte("hello world") // 11 bytes, needs padding

	cipher, err := NewCipher("AES", key)
	assert.NoError(t, err)

	// 使用 CBC 模式，不指定填充（应该使用默认的 PKCS7）
	cbc, err := cipher.NewCBC(iv)
	assert.NoError(t, err)

	// 加密
	encrypted, err := cbc.Encrypt(plaintext)
	assert.NoError(t, err)
	assert.NotEqual(t, plaintext, []byte(encrypted))

	// 解密
	decrypted, err := cbc.Decrypt(encrypted)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, []byte(decrypted))

	// 使用 ECB 模式，不指定填充（应该使用默认的 PKCS7）
	ecb, err := cipher.NewECB()
	assert.NoError(t, err)

	// 加密
	encrypted, err = ecb.Encrypt(plaintext)
	assert.NoError(t, err)
	assert.NotEqual(t, plaintext, []byte(encrypted))

	// 解密
	decrypted, err = ecb.Decrypt(encrypted)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, []byte(decrypted))
}

// ==================== GCM Nonce 大小 ====================

func TestGCM_NonceSize(t *testing.T) {
	key := []byte("0123456789abcdef")
	c, err := NewCipher("AES", key)
	assert.NoError(t, err)

	gcm, err := c.NewGCMWithRandomNonce()
	assert.NoError(t, err)

	// 加密一个空消息来验证 nonce 大小
	encrypted, err := gcm.Encrypt([]byte{})
	assert.NoError(t, err)
	// 对于空消息，长度应该是 nonceSize + tagSize (12 + 16 = 28)
	assert.Equal(t, 28, len(encrypted))
}

// ==================== CBC IV 长度校验 ====================

func TestCBC_IVLength(t *testing.T) {
	key := []byte("0123456789abcdef")
	cipher, err := NewCipher("AES", key)
	assert.NoError(t, err)

	// IV 长度不正确
	iv := []byte("short")
	_, err = cipher.NewCBC(iv)
	assert.Error(t, err)

	// IV 长度正确
	iv = []byte("0123456789abcdef")
	_, err = cipher.NewCBC(iv)
	assert.NoError(t, err)
}

// ==================== 包级 BlockSize 函数 ====================

func TestBlockSize(t *testing.T) {
	blockSize, ivSize, err := crypto.BlockSize("AES")
	assert.NoError(t, err)
	assert.Equal(t, 16, blockSize)
	assert.Equal(t, 16, ivSize)

	blockSize, ivSize, err = crypto.BlockSize("SM4")
	assert.NoError(t, err)
	assert.Equal(t, 16, blockSize)
	assert.Equal(t, 16, ivSize)

	// 未知算法应返回错误
	_, _, err = crypto.BlockSize("INVALID")
	assert.Error(t, err)
}

// ==================== ECB 模式 ====================

func TestECB(t *testing.T) {
	key := []byte("0123456789abcdef")
	cipher, err := NewCipher("AES", key)
	assert.NoError(t, err)

	ecb, err := cipher.NewECB()
	assert.NoError(t, err)

	plaintext := []byte("hello world!!!") // 填充后对齐块
	encrypted, err := ecb.Encrypt(plaintext)
	assert.NoError(t, err)
	assert.NotEqual(t, plaintext, []byte(encrypted))

	decrypted, err := ecb.Decrypt(encrypted)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, []byte(decrypted))
}

// ==================== 并发安全 ====================

func TestSymmetric_Concurrent(t *testing.T) {
	key := []byte("0123456789abcdef")
	plaintext := []byte("hello world")

	cipher, err := NewCipher("AES", key)
	assert.NoError(t, err)

	gcm, err := cipher.NewGCMWithRandomNonce()
	assert.NoError(t, err)

	// 并发加密解密
	done := make(chan bool, 10)
	for range 10 {
		go func() {
			encrypted, err := gcm.Encrypt(plaintext)
			assert.NoError(t, err)
			decrypted, err := gcm.Decrypt(encrypted)
			assert.NoError(t, err)
			assert.True(t, bytes.Equal(plaintext, decrypted))
			done <- true
		}()
	}

	for range 10 {
		<-done
	}
}

// ==================== B 库迁入：SM4-CBC + EmbedIV ====================

func TestSM4CBC_EmbedIV(t *testing.T) {
	key := []byte("1234567890abcdef")
	iv := []byte("1234567890abcdef")
	plain := []byte("hello world")

	c, err := NewCipher("SM4", key)
	assert.NoError(t, err)

	cbc, err := c.NewCBC(iv, EmbedIV())
	assert.NoError(t, err)

	// 加密
	encrypted, err := cbc.Encrypt(plain)
	assert.NoError(t, err)
	assert.NotEqual(t, plain, []byte(encrypted))
	t.Logf("加密结果: %X", encrypted)

	// 解密
	decrypted, err := cbc.Decrypt(encrypted)
	assert.NoError(t, err)
	assert.Equal(t, plain, []byte(decrypted))
	t.Logf("解密结果: %s", string(decrypted))
}

// ==================== AES-192 回归测试 ====================

func TestSymmetric_AES192_BlockSize(t *testing.T) {
	key := []byte("0123456789abcdef01234567") // 24 bytes for AES-192

	cipher, err := NewCipher("AES-192", key)
	assert.NoError(t, err)

	// 方法级 BlockSize() 应返回块大小 16（不是密钥长度 24）
	assert.Equal(t, 16, cipher.BlockSize())

	// IVSize() 应返回 16
	assert.Equal(t, 16, cipher.IVSize())
}

func TestSymmetric_AES192_GCM(t *testing.T) {
	key := []byte("0123456789abcdef01234567") // 24 bytes for AES-192
	plaintext := []byte("hello world")

	cipher, err := NewCipher("AES-192", key)
	assert.NoError(t, err)

	// GCM 往返
	gcm, err := cipher.NewGCMWithRandomNonce()
	assert.NoError(t, err)

	encrypted, err := gcm.Encrypt(plaintext)
	assert.NoError(t, err)

	decrypted, err := gcm.Decrypt(encrypted)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, []byte(decrypted))
}

func TestSymmetric_AES192_CBC(t *testing.T) {
	key := []byte("0123456789abcdef01234567") // 24 bytes
	iv := []byte("abcdef0123456789")          // 16 bytes IV
	plaintext := []byte("hello world")

	cipher, err := NewCipher("AES-192", key)
	assert.NoError(t, err)

	// AES-192 用 16 字节 IV 不应报错（块大小为 16，修复前的 bug：会错误拒绝 16B IV）
	cbc, err := cipher.NewCBC(iv)
	assert.NoError(t, err)

	encrypted, err := cbc.Encrypt(plaintext)
	assert.NoError(t, err)

	decrypted, err := cbc.Decrypt(encrypted)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, []byte(decrypted))
}

// ==================== AES-256 回归测试 ====================

func TestSymmetric_AES256_BlockSize(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef") // 32 bytes for AES-256

	cipher, err := NewCipher("AES-256", key)
	assert.NoError(t, err)

	// 方法级 BlockSize() 应返回块大小 16（不是密钥长度 32）
	assert.Equal(t, 16, cipher.BlockSize())

	// IVSize() 应返回 16
	assert.Equal(t, 16, cipher.IVSize())
}

func TestSymmetric_AES256_GCM(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef") // 32 bytes for AES-256
	plaintext := []byte("hello world")

	cipher, err := NewCipher("AES-256", key)
	assert.NoError(t, err)

	// GCM 往返
	gcm, err := cipher.NewGCMWithRandomNonce()
	assert.NoError(t, err)

	encrypted, err := gcm.Encrypt(plaintext)
	assert.NoError(t, err)

	decrypted, err := gcm.Decrypt(encrypted)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, []byte(decrypted))
}

func TestSymmetric_AES256_CBC(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	iv := []byte("abcdef0123456789")                  // 16 bytes IV
	plaintext := []byte("hello world")

	cipher, err := NewCipher("AES-256", key)
	assert.NoError(t, err)

	// AES-256 用 16 字节 IV 不应报错（块大小为 16，修复前的 bug：会错误拒绝 16B IV）
	cbc, err := cipher.NewCBC(iv)
	assert.NoError(t, err)

	encrypted, err := cbc.Encrypt(plaintext)
	assert.NoError(t, err)

	decrypted, err := cbc.Decrypt(encrypted)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, []byte(decrypted))
}

// ==================== EmbedIV 行为测试 ====================

func TestEmbedIV_Behavior(t *testing.T) {
	key := []byte("0123456789abcdef")
	iv := []byte("abcdef0123456789")
	plaintext := []byte("hello world")

	c, err := NewCipher("AES", key)
	assert.NoError(t, err)

	// 使用 EmbedIV 的 CBC
	cbcEmbed, err := c.NewCBC(iv, EmbedIV())
	assert.NoError(t, err)

	encryptedEmbed, err := cbcEmbed.Encrypt(plaintext)
	assert.NoError(t, err)

	// EmbedIV 后密文前缀应为 IV（前 16 字节）
	assert.Equal(t, iv, []byte(encryptedEmbed)[:16], "EmbedIV 后密文前缀应为 IV")

	// 不使用 EmbedIV 的 CBC
	cbcNoEmbed, err := c.NewCBC(iv)
	assert.NoError(t, err)

	encryptedNoEmbed, err := cbcNoEmbed.Encrypt(plaintext)
	assert.NoError(t, err)

	// EmbedIV 密文比非 EmbedIV 密文长一个块大小（16 字节 = IV 长度）
	assert.Equal(t, len(encryptedNoEmbed)+16, len(encryptedEmbed),
		"EmbedIV 密文应比非 EmbedIV 密文长一个块大小")

	// 验证使用 EmbedIV 后仍能正确解密
	decrypted, err := cbcEmbed.Decrypt(encryptedEmbed)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, []byte(decrypted))
}

// ==================== EmbedNonce 行为测试 ====================

func TestEmbedNonce_Behavior(t *testing.T) {
	key := []byte("0123456789abcdef")
	nonce := []byte("0123456789ab") // 12 bytes
	plaintext := []byte("hello world")

	c, err := NewCipher("AES", key)
	assert.NoError(t, err)

	// 危险路径：固定 nonce + EmbedNonce——同一对象每次 Encrypt 都把同一 nonce
	// 嵌入前缀，两次加密即构成 nonce 重用（GCM 机密性完全丧失）。
	// 该断言固化的是"已知危险行为"而非推荐用法：仅用于固定格式兼容场景。
	gcmEmbed, err := c.NewGCM(nonce, EmbedNonce())
	assert.NoError(t, err)

	enc1, err := gcmEmbed.Encrypt(plaintext)
	assert.NoError(t, err)
	enc2, err := gcmEmbed.Encrypt(plaintext)
	assert.NoError(t, err)

	// 危险行为确认：两次加密前缀（前 12 字节）相同，均为同一固定 nonce。
	assert.Equal(t, nonce, []byte(enc1)[:12], "固定 nonce+EmbedNonce 前缀为同一 nonce（危险行为，非推荐用法）")
	assert.Equal(t, []byte(enc1)[:12], []byte(enc2)[:12], "固定 nonce+EmbedNonce 两次加密复用同一 nonce（危险行为）")

	// 安全路径：nil nonce + EmbedNonce——每次 Encrypt 随机生成新 nonce 并前置。
	gcmSafe, err := c.NewGCM(nil, EmbedNonce())
	assert.NoError(t, err)

	safe1, err := gcmSafe.Encrypt(plaintext)
	assert.NoError(t, err)
	safe2, err := gcmSafe.Encrypt(plaintext)
	assert.NoError(t, err)

	// 安全行为确认：两次加密前缀（前 12 字节）不同（随机 nonce）。
	assert.NotEqual(t, []byte(safe1)[:12], []byte(safe2)[:12], "nil+EmbedNonce 两次加密 nonce 必须不同（安全路径）")

	// 验证使用 EmbedNonce 后仍能正确解密
	decrypted, err := gcmEmbed.Decrypt(enc1)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, []byte(decrypted))

	decrypted2, err := gcmSafe.Decrypt(safe1)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, []byte(decrypted2))
}

// ==================== GCM nonce / AAD 不可变（引用拷贝） ====================

func TestGCM_NonceImmutable(t *testing.T) {
	key := []byte("0123456789abcdef")
	nonce := []byte("0123456789ab") // 12 bytes
	plaintext := []byte("immutable nonce test")

	c, err := NewCipher("AES", key)
	assert.NoError(t, err)

	// 注意：固定 nonce + EmbedNonce 属危险路径（同一对象多次 Encrypt 即 nonce 重用），
	// 本测试仅验证构造后的 nonce 拷贝不可变性，不构成推荐用法（详见 NewGCM 文档）。
	gcm, err := c.NewGCM(nonce, EmbedNonce())
	assert.NoError(t, err)

	// 构造后修改原 nonce 切片：内部应持有拷贝，不受影响
	nonce[0] = 'X'

	encrypted, err := gcm.Encrypt(plaintext)
	assert.NoError(t, err)
	// EmbedNonce 路径密文前缀应为原始 nonce（拷贝保存），而非被修改后的值
	assert.Equal(t, []byte("0123456789ab"), []byte(encrypted)[:12],
		"修改原 nonce 不应影响已构造的 GCM 对象")

	decrypted, err := gcm.Decrypt(encrypted)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, []byte(decrypted))
}

func TestWithAAD_Immutable(t *testing.T) {
	key := []byte("0123456789abcdef")
	aad := []byte("original aad")
	plaintext := []byte("immutable aad test")

	c, err := NewCipher("AES", key)
	assert.NoError(t, err)

	// gcm1 保存 WithAAD(aad) 构造时的 aad 值（拷贝）
	gcm1, err := c.NewGCM(nil, WithAAD(aad), EmbedNonce())
	assert.NoError(t, err)

	// 构造后修改原 aad：gcm1 内部应持有拷贝（原始 aad），不受影响
	aad[0] = 'X'

	// gcm2 使用被修改后的 aad 值加密
	gcm2, err := c.NewGCM(nil, WithAAD(aad), EmbedNonce())
	assert.NoError(t, err)
	encrypted, err := gcm2.Encrypt(plaintext)
	assert.NoError(t, err)

	// gcm1 用原始 aad（拷贝）解密 gcm2 用修改后 aad 加密的密文：认证必须失败
	_, err = gcm1.Decrypt(encrypted)
	assert.Error(t, err, "拷贝保存的原始 AAD 不应能通过修改后 AAD 的密文认证")

	// gcm1 自身加解密往返正常
	encrypted1, err := gcm1.Encrypt(plaintext)
	assert.NoError(t, err)
	decrypted1, err := gcm1.Decrypt(encrypted1)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, []byte(decrypted1))
}

// ==================== StreamCipher.Stream ====================

func TestStreamCipher_Stream(t *testing.T) {
	key := []byte("0123456789abcdef")
	iv := []byte("abcdef0123456789")
	plaintext := []byte("hello world, streaming test!")

	c, err := NewCipher("AES", key)
	assert.NoError(t, err)

	// 加密：XORKeyStream
	enc, err := c.NewCTR(iv)
	assert.NoError(t, err)
	ciphertext := enc.XORKeyStream(plaintext)

	// 解密：Stream(io.Reader) 返回的 reader 读出明文
	dec, err := c.NewCTR(iv)
	assert.NoError(t, err)
	got, err := io.ReadAll(dec.Stream(bytes.NewReader(ciphertext)))
	assert.NoError(t, err)
	assert.Equal(t, plaintext, got)
}

// ==================== NewCTR 非法 IV 长度返回 error（不 panic） ====================

func TestNewCTR_InvalidIVLength(t *testing.T) {
	key := []byte("0123456789abcdef")
	c, err := NewCipher("AES", key)
	assert.NoError(t, err)

	// 非法长度：返回 error，不得触发标准库 cipher.NewCTR panic
	_, err = c.NewCTR(make([]byte, 15))
	assert.Error(t, err, "15B IV 应返回错误")
	_, err = c.NewCTR(nil)
	assert.Error(t, err, "nil IV 应返回错误")
	_, err = c.NewCTR(make([]byte, 17))
	assert.Error(t, err, "17B IV 应返回错误")

	// 合法长度：正常构造且可加解密
	iv := make([]byte, 16)
	s, err := c.NewCTR(iv)
	require.NoError(t, err, "16B IV 应正常构造")
	ct := s.XORKeyStream([]byte("hello"))
	assert.Len(t, ct, 5)

	// DES（8B 块）的合法/非法长度
	c8, err := NewCipher("DES", []byte("01234567"))
	assert.NoError(t, err)
	_, err = c8.NewCTR(make([]byte, 8))
	require.NoError(t, err, "DES 8B IV 应正常构造")
	_, err = c8.NewCTR(make([]byte, 16))
	assert.Error(t, err, "DES 16B IV 应返回错误")
}

// ==================== GCM NonceSize ====================

func TestGCM_NonceSize_Method(t *testing.T) {
	key := []byte("0123456789abcdef")
	c, err := NewCipher("AES", key)
	assert.NoError(t, err)

	gcm, err := c.NewGCMWithRandomNonce()
	assert.NoError(t, err)
	// NonceSize 不在 CipherMode 接口上，通过类型断言访问
	type nonceSizer interface{ NonceSize() int }
	assert.Equal(t, 12, gcm.(nonceSizer).NonceSize())
}

// ==================== GCM 固定 nonce（embednonce=false 路径）====================

func TestGCM_FixedNonce(t *testing.T) {
	key := []byte("0123456789abcdef")
	nonce := []byte("0123456789ab")
	plaintext := []byte("fixed nonce test")

	c, err := NewCipher("AES", key)
	assert.NoError(t, err)

	// 不 EmbedNonce、固定 nonce → copy(nonce, a.nonce) 路径
	gcm, err := c.NewGCM(nonce)
	assert.NoError(t, err)

	encrypted, err := gcm.Encrypt(plaintext)
	assert.NoError(t, err)
	assert.Equal(t, len(plaintext)+16, len(encrypted)) // ciphertext + tag

	decrypted, err := gcm.Decrypt(encrypted)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, []byte(decrypted))
}

// ==================== GCM Decrypt 密文过短 ====================

func TestGCM_Decrypt_TooShort(t *testing.T) {
	key := []byte("0123456789abcdef")
	c, err := NewCipher("AES", key)
	assert.NoError(t, err)

	gcm, err := c.NewGCMWithRandomNonce() // embednonce=true
	assert.NoError(t, err)

	_, err = gcm.Decrypt([]byte("short"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ciphertext too short")
}

// ==================== NewCBC WithAAD 返回错误 ====================

func TestCBC_WithAAD_Rejected(t *testing.T) {
	key := []byte("0123456789abcdef")
	iv := []byte("abcdef0123456789")
	c, err := NewCipher("AES", key)
	assert.NoError(t, err)

	_, err = c.NewCBC(iv, WithAAD([]byte("aad")))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "WithAAD 仅支持 GCM")
}

// ==================== PKCS7 UnPadding 统一错误（P1 C2） ====================

func TestPKCS7UnPadding_Errors(t *testing.T) {
	key := []byte("0123456789abcdef")
	c, err := NewCipher("AES", key)
	assert.NoError(t, err)

	sym := c.(*symmetric)
	block := sym.Block()

	padding := crypto.PKCS7{}
	cases := [][]byte{
		// empty src
		{},
		// unpadding > BlockSize（17 > 16）
		func() []byte { b := make([]byte, 16); b[15] = 17; return b }(),
		// unpadding == 0
		func() []byte { b := make([]byte, 16); b[15] = 0; return b }(),
		// length < unpadding
		{0x02, 0x03},
		// pad 字节不匹配：最后字节声明 2 字节填充，但倒数第二字节不对
		{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 0xFF, 2},
	}

	for i, tc := range cases {
		_, err := padding.UnPadding(block.BlockSize(), tc)
		// 所有失败分支必须返回同一哨兵错误且消息完全一致（消除 padding oracle 判据）
		assert.ErrorIs(t, err, crypto.ErrInvalidPadding, "case %d", i)
		assert.Equal(t, "invalid padding", err.Error(), "case %d", i)
	}
}

// ==================== NewCipher 密钥长度严格校验（P1 C1） ====================

func TestNewCipher_KeyLengthStrict(t *testing.T) {
	// AES-256 配 16 字节密钥：必须拒绝（防止弱化降级）
	_, err := NewCipher("AES-256", make([]byte, 16))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid key length")

	// AES-128 配 32 字节密钥：必须拒绝
	_, err = NewCipher("AES-128", make([]byte, 32))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid key length")

	// AES-192 必须精确 24 字节
	_, err = NewCipher("AES-192", make([]byte, 16))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid key length")

	// 泛名 AES 允许 16/24/32 三选一
	for _, l := range []int{16, 24, 32} {
		c, err := NewCipher("AES", make([]byte, l))
		require.NoError(t, err, "AES key length %d 应被接受", l)
		assert.NotNil(t, c)
	}
}

func TestCBC_Decrypt_EmbedIV_TooShort(t *testing.T) {
	key := []byte("0123456789abcdef")
	iv := []byte("abcdef0123456789")
	c, err := NewCipher("AES", key)
	assert.NoError(t, err)

	cbc, err := c.NewCBC(iv, EmbedIV())
	assert.NoError(t, err)

	_, err = cbc.Decrypt([]byte("short"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ciphertext too short")
}

// ==================== GCM nonce 长度校验（P0 安全修复） ====================

func TestGCM_InvalidNonceLength(t *testing.T) {
	key := []byte("0123456789abcdef")
	c, err := NewCipher("AES", key)
	assert.NoError(t, err)

	// 8 字节 nonce（过短）：修复前被补零到 12 字节，导致 nonce 碰撞
	_, err = c.NewGCM(make([]byte, 8))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid nonce length")

	// 16 字节 nonce（过长）：修复前被静默截断到 12 字节，导致 nonce 碰撞
	_, err = c.NewGCM(make([]byte, 16))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid nonce length")

	// 两条前 12 字节相同、仅尾部不同的 16 字节 nonce 必须均被拒绝（防截断碰撞回归）
	nonceA := make([]byte, 16)
	nonceB := make([]byte, 16)
	copy(nonceA, []byte("0123456789ab"))
	copy(nonceB, []byte("0123456789ab"))
	nonceB[15] = 0xFF
	_, err = c.NewGCM(nonceA)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid nonce length")
	_, err = c.NewGCM(nonceB)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid nonce length")

	// EmbedNonce 下同样必须拒绝非法长度（修复前被静默截断/补零，nonce 碰撞面与无 EmbedNonce 相同）
	_, err = c.NewGCM(make([]byte, 16), EmbedNonce())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid nonce length")
	_, err = c.NewGCM(make([]byte, 8), EmbedNonce())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid nonce length")

	// EmbedNonce 下 nil nonce 仍合法（Encrypt 随机生成并嵌入）
	gcm, err := c.NewGCM(nil, EmbedNonce())
	assert.NoError(t, err)
	sealed, err := gcm.Encrypt([]byte("ok"))
	assert.NoError(t, err)
	decrypted, err := gcm.Decrypt(sealed)
	assert.NoError(t, err)
	assert.Equal(t, []byte("ok"), []byte(decrypted))
}

func TestGCM_NilNonce_NoEmbed(t *testing.T) {
	key := []byte("0123456789abcdef")
	c, err := NewCipher("AES", key)
	assert.NoError(t, err)

	// nil nonce 且未启用 EmbedNonce：修复前 Decrypt 直接 panic
	_, err = c.NewGCM(nil)
	assert.Error(t, err)
}

// ==================== CBC/ECB 解密非对齐密文防护（P0 安全修复） ====================

func TestCBC_Decrypt_Unaligned(t *testing.T) {
	key := []byte("0123456789abcdef")
	iv := []byte("abcdef0123456789")
	c, err := NewCipher("AES", key)
	assert.NoError(t, err)

	cbc, err := c.NewCBC(iv, EmbedIV())
	assert.NoError(t, err)

	// 17 字节（16 字节 IV + 1 字节主体）：修复前 CryptBlocks 触发标准库 panic
	require.NotPanics(t, func() {
		_, err = cbc.Decrypt(make([]byte, 17))
	})
	assert.Error(t, err)

	// 31 字节（16 字节 IV + 15 字节主体）：非对齐，同样必须返回 error 而非 panic
	require.NotPanics(t, func() {
		_, err = cbc.Decrypt(make([]byte, 31))
	})
	assert.Error(t, err)
}

func TestECB_Decrypt_Unaligned(t *testing.T) {
	key := []byte("0123456789abcdef")
	c, err := NewCipher("AES", key)
	assert.NoError(t, err)

	ecb, err := c.NewECB()
	assert.NoError(t, err)

	// 15 字节密文：修复前切片越界 panic
	require.NotPanics(t, func() {
		_, err = ecb.Decrypt(make([]byte, 15))
	})
	assert.Error(t, err)

	// 17 字节密文：非对齐，同样必须返回 error 而非 panic
	require.NotPanics(t, func() {
		_, err = ecb.Decrypt(make([]byte, 17))
	})
	assert.Error(t, err)
}

// ==================== CFB 模式测试 ====================

func TestSymmetric_AES_CFB(t *testing.T) {
	key := []byte("0123456789abcdef")
	iv := []byte("abcdef0123456789")
	plaintext := []byte("hello world, this is a CFB mode test")

	c, err := NewCipher("AES", key)
	assert.NoError(t, err)

	cfb, err := c.NewCFB(iv)
	assert.NoError(t, err)

	encrypted, err := cfb.Encrypt(plaintext)
	assert.NoError(t, err)
	assert.NotEqual(t, plaintext, []byte(encrypted))

	decrypted, err := cfb.Decrypt(encrypted)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, []byte(decrypted))
}

func TestSymmetric_AES_CFB_EmbedIV(t *testing.T) {
	key := []byte("0123456789abcdef")
	iv := []byte("abcdef0123456789")
	plaintext := []byte("hello world, testing embed IV in CFB mode")

	c, err := NewCipher("AES", key)
	assert.NoError(t, err)

	cfb, err := c.NewCFB(iv, EmbedIV())
	assert.NoError(t, err)

	encrypted, err := cfb.Encrypt(plaintext)
	assert.NoError(t, err)
	assert.NotEqual(t, plaintext, []byte(encrypted))

	// Check that the first 16 bytes are the IV
	assert.Equal(t, iv, []byte(encrypted)[:16])

	decrypted, err := cfb.Decrypt(encrypted)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, []byte(decrypted))
}

// ==================== OFB 模式测试 ====================

func TestSymmetric_AES_OFB(t *testing.T) {
	key := []byte("0123456789abcdef")
	iv := []byte("abcdef0123456789")
	plaintext := []byte("hello world, this is a OFB mode test")

	c, err := NewCipher("AES", key)
	assert.NoError(t, err)

	ofb, err := c.NewOFB(iv)
	assert.NoError(t, err)

	encrypted, err := ofb.Encrypt(plaintext)
	assert.NoError(t, err)
	assert.NotEqual(t, plaintext, []byte(encrypted))

	decrypted, err := ofb.Decrypt(encrypted)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, []byte(decrypted))
}

func TestSymmetric_AES_OFB_EmbedIV(t *testing.T) {
	key := []byte("0123456789abcdef")
	iv := []byte("abcdef0123456789")
	plaintext := []byte("hello world, testing embed IV in OFB mode")

	c, err := NewCipher("AES", key)
	assert.NoError(t, err)

	ofb, err := c.NewOFB(iv, EmbedIV())
	assert.NoError(t, err)

	encrypted, err := ofb.Encrypt(plaintext)
	assert.NoError(t, err)
	assert.NotEqual(t, plaintext, []byte(encrypted))

	// Check that the first 16 bytes are the IV
	assert.Equal(t, iv, []byte(encrypted)[:16])

	decrypted, err := ofb.Decrypt(encrypted)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, []byte(decrypted))
}

// ==================== CFB 并发安全测试 ====================

func TestSymmetric_CFB_Concurrent(t *testing.T) {
	key := []byte("0123456789abcdef")
	iv := []byte("abcdef0123456789")
	plaintext := []byte("concurrent test data")

	c, err := NewCipher("AES", key)
	assert.NoError(t, err)

	done := make(chan bool, 10)
	for range 10 {
		go func() {
			cfb, err := c.NewCFB(iv)
			assert.NoError(t, err)
			encrypted, err := cfb.Encrypt(plaintext)
			assert.NoError(t, err)
			decrypted, err := cfb.Decrypt(encrypted)
			assert.NoError(t, err)
			assert.Equal(t, plaintext, []byte(decrypted))
			done <- true
		}()
	}

	for range 10 {
		<-done
	}
}

// ==================== OFB 并发安全测试 ====================

func TestSymmetric_OFB_Concurrent(t *testing.T) {
	key := []byte("0123456789abcdef")
	iv := []byte("abcdef0123456789")
	plaintext := []byte("concurrent test data")

	c, err := NewCipher("AES", key)
	assert.NoError(t, err)

	done := make(chan bool, 10)
	for range 10 {
		go func() {
			ofb, err := c.NewOFB(iv)
			assert.NoError(t, err)
			encrypted, err := ofb.Encrypt(plaintext)
			assert.NoError(t, err)
			decrypted, err := ofb.Decrypt(encrypted)
			assert.NoError(t, err)
			assert.Equal(t, plaintext, []byte(decrypted))
			done <- true
		}()
	}

	for range 10 {
		<-done
	}
}

// ==================== CFB/OFB 与不同算法测试 ====================

func TestSymmetric_CFB_OFB_DifferentAlgorithms(t *testing.T) {
	// 测试 SM4 的 CFB 模式
	key := []byte("0123456789abcdef")
	iv := []byte("abcdef0123456789")
	plaintext := []byte("test with SM4 algorithm")

	c, err := NewCipher("SM4", key)
	assert.NoError(t, err)

	cfb, err := c.NewCFB(iv)
	assert.NoError(t, err)

	encrypted, err := cfb.Encrypt(plaintext)
	assert.NoError(t, err)
	decrypted, err := cfb.Decrypt(encrypted)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, []byte(decrypted))

	// 测试 SM4 的 OFB 模式
	ofb, err := c.NewOFB(iv)
	assert.NoError(t, err)

	encrypted, err = ofb.Encrypt(plaintext)
	assert.NoError(t, err)
	decrypted, err = ofb.Decrypt(encrypted)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, []byte(decrypted))
}

// ==================== 随机 IV 构造（P1 H7 防呆修复） ====================
// 固定 IV 下同一 mode 对象重复 Encrypt 复用相同 keystream（C1⊕C2 = P1⊕P2 直接泄露明文）。
// 随机 IV 构造每次 Encrypt 生成全新随机 IV 并嵌入密文前缀，Decrypt 自动提取还原，
// 同一对象可安全重复 Encrypt。

func TestSymmetric_WithRandomIV_UniqueCiphertext(t *testing.T) {
	key := []byte("0123456789abcdef")
	plaintext := []byte("hello world, random IV unique test")

	c, err := NewCipher("AES", key)
	require.NoError(t, err)

	builders := []struct {
		name  string
		build func() (crypto.CipherMode, error)
	}{
		{"CBC", func() (crypto.CipherMode, error) { return c.NewCBCWithRandomIV() }},
		{"CFB", func() (crypto.CipherMode, error) { return c.NewCFBWithRandomIV() }},
		{"OFB", func() (crypto.CipherMode, error) { return c.NewOFBWithRandomIV() }},
	}

	for _, tt := range builders {
		t.Run(tt.name, func(t *testing.T) {
			mode, err := tt.build()
			require.NoError(t, err)

			enc1, err := mode.Encrypt(plaintext)
			require.NoError(t, err)
			enc2, err := mode.Encrypt(plaintext)
			require.NoError(t, err)

			// 同一对象两次 Encrypt 必须产生不同密文，且嵌入的随机 IV 前缀不同
			assert.NotEqual(t, []byte(enc1), []byte(enc2))
			assert.NotEqual(t, []byte(enc1)[:16], []byte(enc2)[:16])
			// 密文长度大于明文（含嵌入 IV；CBC 另含 PKCS7 填充）
			assert.Greater(t, len([]byte(enc1)), len(plaintext))

			// 往返：密文含嵌入 IV，Decrypt 无需再传 IV 即还原
			dec1, err := mode.Decrypt(enc1)
			require.NoError(t, err)
			assert.Equal(t, plaintext, []byte(dec1))

			dec2, err := mode.Decrypt(enc2)
			require.NoError(t, err)
			assert.Equal(t, plaintext, []byte(dec2))
		})
	}
}

// TestSymmetric_WithRandomIV_WithPadding 验证随机 IV 构造函数可正常组合 WithPadding 选项。
func TestSymmetric_WithRandomIV_WithPadding(t *testing.T) {
	key := []byte("0123456789abcdef")
	// 16 字节倍数明文，配合 NoPadding 验证选项传递路径
	plaintext := []byte("random NoPadding")

	c, err := NewCipher("AES", key)
	require.NoError(t, err)

	cbc, err := c.NewCBCWithRandomIV(WithPadding(crypto.NoPadding{}))
	require.NoError(t, err)

	encrypted, err := cbc.Encrypt(plaintext)
	require.NoError(t, err)
	// NoPadding + 嵌入 IV：密文 = 明文 + 16 字节 IV
	assert.Len(t, []byte(encrypted), len(plaintext)+16)

	decrypted, err := cbc.Decrypt(encrypted)
	require.NoError(t, err)
	assert.Equal(t, plaintext, []byte(decrypted))
}

// ==================== CBC/CFB/OFB IV 不可变（构造后修改原 iv 不受影响） ====================

func TestCBC_IVImmutable(t *testing.T) {
	key := []byte("0123456789abcdef")
	iv := []byte("abcdef0123456789")
	plaintext := []byte("immutable iv test")

	c, err := NewCipher("AES", key)
	require.NoError(t, err)

	// 构造对象后修改原 iv 切片：内部应持有拷贝，加解密往返不受影响
	cbc, err := c.NewCBC(iv)
	require.NoError(t, err)
	iv[0] = 'X'

	encrypted, err := cbc.Encrypt(plaintext)
	require.NoError(t, err)
	decrypted, err := cbc.Decrypt(encrypted)
	require.NoError(t, err)
	assert.Equal(t, plaintext, []byte(decrypted))
}

func TestStream_IVImmutable(t *testing.T) {
	key := []byte("0123456789abcdef")
	plaintext := []byte("immutable stream iv test")

	c, err := NewCipher("AES", key)
	require.NoError(t, err)

	builders := []struct {
		name  string
		build func(iv []byte) (crypto.CipherMode, error)
	}{
		{"CFB", func(iv []byte) (crypto.CipherMode, error) { return c.NewCFB(iv) }},
		{"OFB", func(iv []byte) (crypto.CipherMode, error) { return c.NewOFB(iv) }},
	}

	for _, tt := range builders {
		t.Run(tt.name, func(t *testing.T) {
			iv := []byte("abcdef0123456789")
			mode, err := tt.build(iv)
			require.NoError(t, err)

			// 构造后修改原 iv 切片：内部应持有拷贝，不受影响
			iv[0] = 'X'

			encrypted, err := mode.Encrypt(plaintext)
			require.NoError(t, err)
			decrypted, err := mode.Decrypt(encrypted)
			require.NoError(t, err)
			assert.Equal(t, plaintext, []byte(decrypted))
		})
	}
}

// ==================== 低层 Decrypt 输入不变性（P3 修复） ====================

func TestDecrypt_InputImmutable(t *testing.T) {
	key := []byte("0123456789abcdef")
	iv := []byte("abcdef0123456789")
	nonce := []byte("0123456789ab")
	plaintext := []byte("input immutability low-level")

	c, err := NewCipher("AES", key)
	require.NoError(t, err)

	// 辅助：解密并断言输入密文完全不变
	check := func(t *testing.T, name string, m crypto.CipherMode, ciphertext []byte) {
		t.Helper()
		original := append([]byte(nil), ciphertext...)
		dec, err := m.Decrypt(ciphertext)
		require.NoError(t, err, name)
		assert.Equal(t, plaintext, []byte(dec), name)
		require.Equal(t, original, ciphertext, "%s 解密不应修改输入密文", name)
	}

	t.Run("CBC_EmbedIV", func(t *testing.T) {
		m, err := c.NewCBC(iv, EmbedIV())
		require.NoError(t, err)
		enc, err := m.Encrypt(plaintext)
		require.NoError(t, err)
		check(t, "CBC embediv", m, []byte(enc))
	})
	t.Run("CBC_FixedIV", func(t *testing.T) {
		m, err := c.NewCBC(iv)
		require.NoError(t, err)
		enc, err := m.Encrypt(plaintext)
		require.NoError(t, err)
		check(t, "CBC fixed iv", m, []byte(enc))
	})
	t.Run("ECB", func(t *testing.T) {
		m, err := c.NewECB()
		require.NoError(t, err)
		enc, err := m.Encrypt(plaintext)
		require.NoError(t, err)
		check(t, "ECB", m, []byte(enc))
	})
	t.Run("CFB_EmbedIV", func(t *testing.T) {
		m, err := c.NewCFB(iv, EmbedIV())
		require.NoError(t, err)
		enc, err := m.Encrypt(plaintext)
		require.NoError(t, err)
		check(t, "CFB embediv", m, []byte(enc))
	})
	t.Run("CFB_FixedIV", func(t *testing.T) {
		m, err := c.NewCFB(iv)
		require.NoError(t, err)
		enc, err := m.Encrypt(plaintext)
		require.NoError(t, err)
		check(t, "CFB fixed iv", m, []byte(enc))
	})
	t.Run("OFB_EmbedIV", func(t *testing.T) {
		m, err := c.NewOFB(iv, EmbedIV())
		require.NoError(t, err)
		enc, err := m.Encrypt(plaintext)
		require.NoError(t, err)
		check(t, "OFB embediv", m, []byte(enc))
	})
	t.Run("OFB_FixedIV", func(t *testing.T) {
		m, err := c.NewOFB(iv)
		require.NoError(t, err)
		enc, err := m.Encrypt(plaintext)
		require.NoError(t, err)
		check(t, "OFB fixed iv", m, []byte(enc))
	})
	t.Run("GCM_RandomNonce", func(t *testing.T) {
		m, err := c.NewGCMWithRandomNonce()
		require.NoError(t, err)
		enc, err := m.Encrypt(plaintext)
		require.NoError(t, err)
		check(t, "GCM random nonce", m, []byte(enc))
	})
	t.Run("GCM_FixedNonce", func(t *testing.T) {
		m, err := c.NewGCM(nonce)
		require.NoError(t, err)
		enc, err := m.Encrypt(plaintext)
		require.NoError(t, err)
		check(t, "GCM fixed nonce", m, []byte(enc))
	})
	t.Run("CTR", func(t *testing.T) {
		s, err := c.NewCTR(iv)
		require.NoError(t, err)
		ct := s.XORKeyStream(plaintext)
		original := append([]byte(nil), ct...)
		s2, err := c.NewCTR(iv)
		require.NoError(t, err)
		dec := s2.XORKeyStream(ct)
		assert.Equal(t, plaintext, dec)
		require.Equal(t, original, ct, "CTR XORKeyStream 不应修改输入")
	})
}
