package envelope

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fsb2Encrypt 便捷：构造 fsb2 加密器并完整读取容器流。
func fsb2Encrypt(t *testing.T, plain []byte, algorithm string, key []byte) []byte {
	t.Helper()
	fe, err := NewFileEncrypter(key, algorithm)
	require.NoError(t, err)
	er, err := fe.Encrypt(bytes.NewReader(plain), int64(len(plain)))
	require.NoError(t, err)
	ct, err := io.ReadAll(er)
	require.NoError(t, err)
	return ct
}

// fsb2Decrypt 便捷：从容器流自读头部并完整解密。
func fsb2Decrypt(t *testing.T, ct, key []byte) []byte {
	t.Helper()
	dr, err := NewFileDecryptingReader(bytes.NewReader(ct), key)
	require.NoError(t, err)
	pt, err := io.ReadAll(dr)
	require.NoError(t, err)
	return pt
}

// TestFsb2HeaderLayout 头部布局断言：magic/version/algID/baseNonce 随机性/
// totalSize(LE) 与文档字节定义一致。
func TestFsb2HeaderLayout(t *testing.T) {
	plain := randBytes(t, 5000)
	fe, err := NewFileEncrypter(testKey, "SM4")
	require.NoError(t, err)
	er, err := fe.Encrypt(bytes.NewReader(plain), int64(len(plain)))
	require.NoError(t, err)
	ct, err := io.ReadAll(er)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(ct), fsb2HeaderLen)

	h := ct[:fsb2HeaderLen]
	assert.Equal(t, fsb2Magic, string(h[:len(fsb2Magic)]))
	assert.Equal(t, byte(fsb2Version), h[len(fsb2Magic)])
	assert.Equal(t, byte(fsb2AlgIDSM4), h[len(fsb2Magic)+1])
	// baseNonce 必须是随机增量（非全零、非外部可注入）
	nonce := h[len(fsb2Magic)+2 : len(fsb2Magic)+2+fsb2NonceLen]
	assert.False(t, bytes.Equal(nonce, make([]byte, fsb2NonceLen)), "baseNonce 不应为全零")
	assert.Equal(t, uint64(len(plain)), binary.LittleEndian.Uint64(h[fsb2SizeOffset:]))
	// 密文总长 = 头部 + 明文 + 每块 TAG
	assert.Equal(t, fsb2HeaderLen+len(plain)+2*TagSize, len(ct))
}

// TestFsb2RoundTrip 往返：各边界尺寸 Encrypt→Decrypt 全等（容器完全自描述，
// 解密侧不传 totalSize/baseNonce）。
func TestFsb2RoundTrip(t *testing.T) {
	algorithms := []struct {
		name string
		key  []byte
	}{
		{"SM4", []byte("0123456789abcdef")},
		{"AES-128", make([]byte, 16)},
		{"AES-192", make([]byte, 24)},
		{"AES-256", make([]byte, 32)},
	}
	sizes := []int{0, 1, ChunkSize - 1, ChunkSize, ChunkSize + 1, 1024 * 1024}
	for _, a := range algorithms {
		for _, size := range sizes {
			plain := randBytes(t, size)
			ct := fsb2Encrypt(t, plain, a.name, a.key)
			if size == 0 {
				// 空文件：仅头部，无任何块
				assert.Equal(t, fsb2HeaderLen, len(ct), "%s size=%d", a.name, size)
			}
			got := fsb2Decrypt(t, ct, a.key)
			if !bytes.Equal(got, plain) {
				t.Fatalf("%s size=%d roundtrip mismatch", a.name, size)
			}
		}
	}
}

// TestFsb2Length fsb2 EncryptingReader.Length() 精确性：头部 + 公式，且与
// 实际输出的容器流长度一致。
func TestFsb2Length(t *testing.T) {
	fe, err := NewFileEncrypter(testKey, "SM4")
	require.NoError(t, err)
	for _, size := range []int{0, 1, ChunkSize - 1, ChunkSize, ChunkSize + 1} {
		er, err := fe.Encrypt(bytes.NewReader(randBytes(t, size)), int64(size))
		require.NoError(t, err)
		want := int64(fsb2HeaderLen) + int64(size) + int64(TagSize)*((int64(size)+ChunkSize-1)/ChunkSize)
		assert.Equal(t, want, er.Length(), "size=%d", size)
		ct, err := io.ReadAll(er)
		require.NoError(t, err)
		assert.Equal(t, want, int64(len(ct)), "size=%d 实际输出长度", size)
	}
}

// TestFsb2StreamingRead 流式读取：以 1KB 缓冲逐段读解密输出，与原文一致。
func TestFsb2StreamingRead(t *testing.T) {
	plain := randBytes(t, 100*1024)
	ct := fsb2Encrypt(t, plain, "SM4", testKey)

	dr, err := NewFileDecryptingReader(bytes.NewReader(ct), testKey)
	require.NoError(t, err)
	var got []byte
	buf := make([]byte, 1024)
	for {
		n, err := dr.Read(buf)
		got = append(got, buf[:n]...)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("streaming read mismatch")
	}
}

// TestFsb2TamperHeader 头篡改：逐字节翻转头部 28 字节，解密必须失败
//（构造期哨兵错误或 Read 期 GCM AAD 认证失败均可，绝不能成功解密）。
func TestFsb2TamperHeader(t *testing.T) {
	plain := randBytes(t, 5000) // 2 块
	ct := fsb2Encrypt(t, plain, "SM4", testKey)

	for i := 0; i < fsb2HeaderLen; i++ {
		tampered := append([]byte(nil), ct...)
		// 跳过 magic/version/algID 后的篡改需在解密路径验证（该三区由
		// 构造期哨兵拒绝）；baseNonce/totalSize 区篡改由 AAD 认证拒绝。
		tampered[i] ^= 0xFF
		dr, err := NewFileDecryptingReader(bytes.NewReader(tampered), testKey)
		if err != nil {
			continue // 构造期哨兵失败，符合预期
		}
		_, err = io.ReadAll(dr)
		assert.Error(t, err, "篡改头部字节 %d 应解密失败", i)
	}
}

// TestFsb2AlgConfusion 算法混淆：改头声明另一算法必须失败。
// 混淆为同长度算法（SM4→AES-128）时构造通过但 AAD 认证失败；
// 混淆为不同长度算法（SM4→AES-256）时密钥长度校验直接拒绝。
func TestFsb2AlgConfusion(t *testing.T) {
	plain := randBytes(t, 4096)
	ct := fsb2Encrypt(t, plain, "SM4", testKey)

	// SM4→AES-128（密钥同为 16 字节）：构造通过，AAD 认证失败
	same := append([]byte(nil), ct...)
	same[len(fsb2Magic)+1] = fsb2AlgIDAES128
	dr, err := NewFileDecryptingReader(bytes.NewReader(same), testKey)
	require.NoError(t, err, "混淆为同长度算法应能构造（由 AAD 兜底拒绝）")
	_, err = io.ReadAll(dr)
	assert.Error(t, err, "算法混淆（SM4→AES-128）应解密失败")

	// SM4→AES-256（密钥 16 字节不匹配 32 字节）：构造期拒绝
	different := append([]byte(nil), ct...)
	different[len(fsb2Magic)+1] = fsb2AlgIDAES256
	_, err = NewFileDecryptingReader(bytes.NewReader(different), testKey)
	assert.ErrorIs(t, err, ErrFsb2KeyMismatch)
}

// TestFsb2HeaderSentinels 头部哨兵错误：magic/version/未注册 algID/
// 不安全 algID 各返回明确哨兵。
func TestFsb2HeaderSentinels(t *testing.T) {
	ct := fsb2Encrypt(t, randBytes(t, 100), "SM4", testKey)

	// magic 篡改
	badMagic := append([]byte(nil), ct...)
	badMagic[0] ^= 0xFF
	_, err := NewFileDecryptingReader(bytes.NewReader(badMagic), testKey)
	assert.ErrorIs(t, err, ErrFsb2MagicMismatch)

	// version 篡改
	badVer := append([]byte(nil), ct...)
	badVer[len(fsb2Magic)] = fsb2Version + 1
	_, err = NewFileDecryptingReader(bytes.NewReader(badVer), testKey)
	assert.ErrorIs(t, err, ErrFsb2VersionMismatch)

	// 未注册 algID（0x07）
	unknown := append([]byte(nil), ct...)
	unknown[len(fsb2Magic)+1] = 0x07
	_, err = NewFileDecryptingReader(bytes.NewReader(unknown), testKey)
	assert.ErrorIs(t, err, ErrFsb2UnknownAlg)

	// 不安全 algID（DES=0x05 / 3DES=0x06）
	for _, id := range []byte{fsb2AlgIDDES, fsb2AlgID3DES} {
		insecure := append([]byte(nil), ct...)
		insecure[len(fsb2Magic)+1] = id
		_, err = NewFileDecryptingReader(bytes.NewReader(insecure), testKey)
		assert.ErrorIs(t, err, ErrFsb2InsecureAlg, "algID=0x%02x 应报 ErrFsb2InsecureAlg", id)
	}

	// 头部截断
	_, err = NewFileDecryptingReader(bytes.NewReader(ct[:fsb2HeaderLen-1]), testKey)
	assert.ErrorIs(t, err, ErrFsb2BadHeader)

	// totalSize 最高字节（uint64 LE 的 [offset+7]）被篡改为 0xFF → 转 int64
	// 为负值 → ErrFsb2BadSize
	badSize := append([]byte(nil), ct...)
	badSize[fsb2SizeOffset+fsb2SizeLen-1] = 0xFF
	_, err = NewFileDecryptingReader(bytes.NewReader(badSize), testKey)
	assert.ErrorIs(t, err, ErrFsb2BadSize)
}

// TestFsb2KeyLengthMismatch 密钥长度与头部声明算法不匹配：构造期拒绝。
func TestFsb2KeyLengthMismatch(t *testing.T) {
	// 加密侧：AES-256 声明 + 16 字节密钥 → 构造即拒绝
	_, err := NewFileEncrypter(make([]byte, 16), "AES-256")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "key")

	// 解密侧：头部声明 AES-256（32B key 加密），用 16B key 解密 → ErrFsb2KeyMismatch
	ct := fsb2Encrypt(t, randBytes(t, 100), "AES-256", make([]byte, 32))
	_, err = NewFileDecryptingReader(bytes.NewReader(ct), make([]byte, 16))
	assert.ErrorIs(t, err, ErrFsb2KeyMismatch)
}

// TestFsb2WrongKey 正确密钥结构但内容错误：GCM 认证失败（防伪装）。
func TestFsb2WrongKey(t *testing.T) {
	ct := fsb2Encrypt(t, randBytes(t, 5000), "SM4", testKey)
	wrong := bytes.Repeat([]byte{0xAB}, len(testKey))
	dr, err := NewFileDecryptingReader(bytes.NewReader(ct), wrong)
	require.NoError(t, err)
	_, err = io.ReadAll(dr)
	assert.Error(t, err, "错误密钥应认证失败")
}

// TestFsb2TooShortHeader 非 fsb2 数据流（如凭空 28 字节）按 magic 拒绝。
func TestFsb2TooShortHeader(t *testing.T) {
	_, err := NewFileDecryptingReader(bytes.NewReader(randBytes(t, 100)), testKey)
	// 随机数据 magic 几乎不可能匹配，应报 magic 或未知错误（绝不 panic 成功）
	if err == nil {
		t.Fatal("随机数据不应被当作合法 fsb2 容器")
	}
}

// TestFsb2UnsupportedAlgorithm 加密侧不支持的算法/泛名归一验证。
func TestFsb2UnsupportedAlgorithm(t *testing.T) {
	// DES/3DES：不安全算法拒绝（Lane A 闸门）
	_, err := NewFileEncrypter(make([]byte, 8), "DES")
	assert.Error(t, err)
	_, err = NewFileEncrypter(make([]byte, 24), "3DES")
	assert.Error(t, err)
	// 非对称/协商算法名拒绝
	_, err = NewFileEncrypter(make([]byte, 16), "RSA")
	assert.Error(t, err)
	// 泛名归一：aes 归一为 AES-128（密钥 16 字节合法）
	fe, err := NewFileEncrypter(make([]byte, 16), "aes")
	require.NoError(t, err)
	assert.Equal(t, "AES-128", fe.algorithm)
	// 未注册名拒绝
	_, err = NewFileEncrypter(make([]byte, 16), "NOPE")
	assert.Error(t, err)
}

// TestFsb2ErrSizeMismatch fsb2 加密实读数 != 声明 totalSize → 既有
// ErrSizeMismatch 机制在 fsb2 下同样生效。
func TestFsb2ErrSizeMismatch(t *testing.T) {
	fe, err := NewFileEncrypter(testKey, "SM4")
	require.NoError(t, err)
	er, err := fe.Encrypt(bytes.NewReader(randBytes(t, 1000)), 500)
	require.NoError(t, err)
	_, err = io.ReadAll(er)
	assert.ErrorIs(t, err, ErrSizeMismatch)
}

// 回归：fsb2 不影响 fsb1 冻结格式（KAT 与既有行为经既有测试覆盖，
// 此处仅确认 fsb1 构造器输出仍不含头部）。
func TestFsb1UnchangedNoHeader(t *testing.T) {
	plain := randBytes(t, 100)
	ct, err := encryptToBytes(t, plain, testNonce(t), int64(len(plain)))
	require.NoError(t, err)
	assert.False(t, bytes.HasPrefix(ct, []byte(fsb2Magic)), "fsb1 输出不得带 fsb2 头部")

	// fsb1 magic 常量冻结不可变
	assert.Equal(t, "fsb1", FormatMagic)
}

// 基准：fsb2 加密吞吐（与 fsb1 同负载，头部开销可忽略）。
func BenchmarkFsb2Encrypt(b *testing.B) {
	const size = 100 * 1024 * 1024
	plain := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, plain); err != nil {
		b.Fatal(err)
	}
	fe, err := NewFileEncrypter(testKey, "SM4")
	if err != nil {
		b.Fatal(err)
	}
	er, err := fe.Encrypt(bytes.NewReader(plain), size)
	if err != nil {
		b.Fatal(err)
	}

	b.SetBytes(size)
	for b.Loop() {
		if _, err := io.Copy(io.Discard, er); err != nil {
			b.Fatal(err)
		}
	}
}