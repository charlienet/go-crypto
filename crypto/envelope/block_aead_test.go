package envelope

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rootcrypto "github.com/charlienet/go-crypto/crypto"
)

// 固定 16 字节 SM4 测试密钥。
var testKey = []byte("0123456789abcdef")

// testNonce 生成随机 12 字节 baseNonce。
func testNonce(t testing.TB) []byte {
	t.Helper()
	nonce := make([]byte, blockNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		t.Fatal(err)
	}
	return nonce
}

func mustCipher(t testing.TB) rootcrypto.Cipher {
	t.Helper()
	c, err := rootcrypto.NewCipher("SM4", testKey)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// randBytes 生成 n 字节伪随机数据。
func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		t.Fatal(err)
	}
	return b
}

func encryptToBytes(t *testing.T, plain []byte, nonce []byte, totalSize int64) ([]byte, error) {
	t.Helper()
	er, err := NewEncryptingReader(bytes.NewReader(plain), mustCipher(t), nonce, totalSize)
	if err != nil {
		t.Fatal(err)
	}
	return io.ReadAll(er)
}

func decryptToBytes(t *testing.T, ct []byte, nonce []byte, totalSize int64) ([]byte, error) {
	t.Helper()
	dr, err := NewDecryptingReader(bytes.NewReader(ct), mustCipher(t), nonce, totalSize)
	if err != nil {
		t.Fatal(err)
	}
	return io.ReadAll(dr)
}

// 1. 往返：各边界大小 Encrypt→Decrypt 全等。
func TestBlockAeadRoundTrip(t *testing.T) {
	sizes := []int{0, 1, 4095, 4096, 4097, 1024 * 1024}
	for _, size := range sizes {
		plain := randBytes(t, size)
		nonce := testNonce(t)

		ct, err := encryptToBytes(t, plain, nonce, int64(size))
		if err != nil {
			t.Fatalf("size=%d encrypt: %v", size, err)
		}
		got, err := decryptToBytes(t, ct, nonce, int64(size))
		if err != nil {
			t.Fatalf("size=%d decrypt: %v", size, err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("size=%d roundtrip mismatch", size)
		}
	}
}

// 2. 篡改密文任意一字节 → 解密失败。
func TestBlockAeadTamperCiphertext(t *testing.T) {
	plain := randBytes(t, 64*1024)
	nonce := testNonce(t)
	ct, err := encryptToBytes(t, plain, nonce, int64(len(plain)))
	if err != nil {
		t.Fatal(err)
	}

	// 翻转第 2 块密文区中间一字节（非 tag 区）。
	tampered := append([]byte(nil), ct...)
	tampered[5000] ^= 0xFF

	if _, err := decryptToBytes(t, tampered, nonce, int64(len(plain))); err == nil {
		t.Fatal("tampered ciphertext decrypted successfully")
	}
}

// 3. 篡改 TAG 任意一字节 → 解密失败。
func TestBlockAeadTamperTag(t *testing.T) {
	plain := randBytes(t, 64*1024)
	nonce := testNonce(t)
	ct, err := encryptToBytes(t, plain, nonce, int64(len(plain)))
	if err != nil {
		t.Fatal(err)
	}

	// 翻转最后一个块的认证标签最后一字节。
	tampered := append([]byte(nil), ct...)
	tampered[len(tampered)-1] ^= 0x01

	if _, err := decryptToBytes(t, tampered, nonce, int64(len(plain))); err == nil {
		t.Fatal("tampered tag decrypted successfully")
	}
}

// 4. 块重排（交换前两块）→ 失败（AAD 块号绑定）。
func TestBlockAeadReorderedBlocks(t *testing.T) {
	plain := randBytes(t, 64*1024) // 16 块
	nonce := testNonce(t)
	ct, err := encryptToBytes(t, plain, nonce, int64(len(plain)))
	if err != nil {
		t.Fatal(err)
	}

	blockLen := ChunkSize + TagSize
	reordered := make([]byte, 0, len(ct))
	reordered = append(reordered, ct[blockLen:2*blockLen]...) // 原第 2 块
	reordered = append(reordered, ct[:blockLen]...)           // 原第 1 块
	reordered = append(reordered, ct[2*blockLen:]...)         // 其余块

	if _, err := decryptToBytes(t, reordered, nonce, int64(len(plain))); err == nil {
		t.Fatal("reordered blocks decrypted successfully")
	}
}

// 5. 删尾块 / 尾部追加块 → 截断 / 过长。
func TestBlockAeadTruncateAndAppend(t *testing.T) {
	plain := randBytes(t, 64*1024)
	nonce := testNonce(t)
	ct, err := encryptToBytes(t, plain, nonce, int64(len(plain)))
	if err != nil {
		t.Fatal(err)
	}
	blockLen := ChunkSize + TagSize

	// 删尾块 → 块数不足 → ErrCipherTruncated
	truncated := ct[:len(ct)-blockLen]
	if _, err := decryptToBytes(t, truncated, nonce, int64(len(plain))); !errors.Is(err, ErrCipherTruncated) {
		t.Fatalf("truncated: got %v, want ErrCipherTruncated", err)
	}

	// 尾部追加一个块 → 超出预期块数 → ErrCipherTooLong
	appended := append(append([]byte(nil), ct...), randBytes(t, blockLen)...)
	if _, err := decryptToBytes(t, appended, nonce, int64(len(plain))); !errors.Is(err, ErrCipherTooLong) {
		t.Fatalf("appended: got %v, want ErrCipherTooLong", err)
	}
}

// 6. 用错误的 totalSize 解密 → 失败（AAD size 绑定）。
func TestBlockAeadWrongTotalSize(t *testing.T) {
	plain := randBytes(t, 5000) // 2 块：4096 + 904
	nonce := testNonce(t)
	ct, err := encryptToBytes(t, plain, nonce, int64(len(plain)))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := decryptToBytes(t, ct, nonce, 4096); err == nil {
		t.Fatal("wrong totalSize decrypted successfully")
	}
	if _, err := decryptToBytes(t, ct, nonce, 10000); err == nil {
		t.Fatal("larger wrong totalSize decrypted successfully")
	}
}

// 7. 篡改 baseNonce → 失败。
func TestBlockAeadWrongNonce(t *testing.T) {
	plain := randBytes(t, 64*1024)
	nonce := testNonce(t)
	ct, err := encryptToBytes(t, plain, nonce, int64(len(plain)))
	if err != nil {
		t.Fatal(err)
	}

	wrong := append([]byte(nil), nonce...)
	wrong[0] ^= 0xFF

	if _, err := decryptToBytes(t, ct, wrong, int64(len(plain))); err == nil {
		t.Fatal("wrong baseNonce decrypted successfully")
	}
}

// 8. 流式行为：以 1KB 缓冲逐段读解密输出，与原文一致。
func TestBlockAeadStreamingRead(t *testing.T) {
	plain := randBytes(t, 100*1024)
	nonce := testNonce(t)
	ct, err := encryptToBytes(t, plain, nonce, int64(len(plain)))
	if err != nil {
		t.Fatal(err)
	}

	dr, err := NewDecryptingReader(bytes.NewReader(ct), mustCipher(t), nonce, int64(len(plain)))
	if err != nil {
		t.Fatal(err)
	}

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

// 9. EncryptingReader 实计数 ≠ totalSize → ErrSizeMismatch。
func TestBlockAeadSizeMismatch(t *testing.T) {
	plain := randBytes(t, 1000)
	nonce := testNonce(t)

	if _, err := encryptToBytes(t, plain, nonce, 2000); !errors.Is(err, ErrSizeMismatch) {
		t.Fatalf("got %v, want ErrSizeMismatch", err)
	}
}

// 9b. EncryptingReader.Length() 精确性：对 0/1/4095/4096/4097/1MB 输入，
// Length() 必须等于公式 totalSize + TagSize*ceil(totalSize/ChunkSize)，
// 且与实际读出的密文流长度一致（供 S3 PutObject ContentLength 使用）。
func TestEncryptingReaderLength(t *testing.T) {
	cases := []struct {
		size int
		want int64
	}{
		{0, 0},
		{1, 1 + TagSize},
		{ChunkSize - 1, ChunkSize - 1 + TagSize},
		{ChunkSize, ChunkSize + TagSize},
		{ChunkSize + 1, ChunkSize + 1 + 2*TagSize},
		{1024 * 1024, 1024*1024 + TagSize*(1024*1024/ChunkSize)},
	}
	for _, tc := range cases {
		er, err := NewEncryptingReader(bytes.NewReader(randBytes(t, tc.size)), mustCipher(t), testNonce(t), int64(tc.size))
		if err != nil {
			t.Fatalf("size=%d NewEncryptingReader: %v", tc.size, err)
		}
		if got := er.Length(); got != tc.want {
			t.Errorf("size=%d Length() = %d, want %d", tc.size, got, tc.want)
		}
		// 实际输出的密文流长度必须与 Length() 一致
		ct, err := io.ReadAll(er)
		if err != nil {
			t.Fatalf("size=%d read: %v", tc.size, err)
		}
		if int64(len(ct)) != tc.want {
			t.Errorf("size=%d actual ciphertext len = %d, want %d", tc.size, len(ct), tc.want)
		}
	}
}

// 10. 空文件往返。
func TestBlockAeadEmptyRoundTrip(t *testing.T) {
	nonce := testNonce(t)

	ct, err := encryptToBytes(t, nil, nonce, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(ct) != 0 {
		t.Fatalf("empty file produced %d ciphertext bytes", len(ct))
	}

	got, err := decryptToBytes(t, ct, nonce, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("empty file decrypted to %d bytes", len(got))
	}

	// 空密文但声明有内容 → 截断
	if _, err := decryptToBytes(t, nil, nonce, 100); !errors.Is(err, ErrCipherTruncated) {
		t.Fatalf("got %v, want ErrCipherTruncated", err)
	}
}

// deriveNonce 单元行为：大端加法、进位与溢出。
func TestDeriveNonce(t *testing.T) {
	// 0 + 0 = 0
	base := make([]byte, blockNonceSize)
	n, err := deriveNonce(base, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(n, base) {
		t.Fatal("derive 0 mismatch")
	}

	// 低 8 字节大端加法：0xFE + 2 = 0x0100
	base = make([]byte, blockNonceSize)
	base[blockNonceSize-1] = 0xFE
	n, err = deriveNonce(base, 2)
	if err != nil {
		t.Fatal(err)
	}
	want := make([]byte, blockNonceSize)
	want[blockNonceSize-2] = 0x01
	if !bytes.Equal(n, want) {
		t.Fatalf("big-endian add: got %X want %X", n, want)
	}

	// 低 64 位全 FF + 1 → 进位到高 32 位
	base = make([]byte, blockNonceSize)
	for i := 4; i < blockNonceSize; i++ {
		base[i] = 0xFF
	}
	n, err = deriveNonce(base, 1)
	if err != nil {
		t.Fatal(err)
	}
	want = make([]byte, blockNonceSize)
	want[3] = 0x01
	if !bytes.Equal(n, want) {
		t.Fatalf("carry: got %X want %X", n, want)
	}

	// 全 FF + 1 → 溢出
	allFF := bytes.Repeat([]byte{0xFF}, blockNonceSize)
	if _, err := deriveNonce(allFF, 1); !errors.Is(err, ErrNonceOverflow) {
		t.Fatalf("got %v, want ErrNonceOverflow", err)
	}

	// 长度非法
	if _, err := deriveNonce([]byte{1, 2, 3}, 0); !errors.Is(err, ErrInvalidBaseNonce) {
		t.Fatalf("got %v, want ErrInvalidBaseNonce", err)
	}
}

// 快速吞吐基准：SM4-GCM 100MB 数据。
func BenchmarkBlockAeadThroughput(b *testing.B) {
	const size = 100 * 1024 * 1024

	plain := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, plain); err != nil {
		b.Fatal(err)
	}
	nonce := testNonce(b)
	c := mustCipher(b)

	b.SetBytes(size)

	for b.Loop() {
		er, err := NewEncryptingReader(bytes.NewReader(plain), c, nonce, size)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, er); err != nil {
			b.Fatal(err)
		}
	}
}

// 解密方向吞吐基准：SM4-GCM 100MB 数据。
func BenchmarkBlockAeadDecrypt(b *testing.B) {
	const size = 100 * 1024 * 1024

	plain := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, plain); err != nil {
		b.Fatal(err)
	}
	nonce := testNonce(b)
	c := mustCipher(b)

	// 预生成密文流（每轮解密相同数据，隔离加密开销）
	er, err := NewEncryptingReader(bytes.NewReader(plain), c, nonce, size)
	if err != nil {
		b.Fatal(err)
	}
	ciphertext, err := io.ReadAll(er)
	if err != nil {
		b.Fatal(err)
	}

	b.SetBytes(size)

	for b.Loop() {
		dr, err := NewDecryptingReader(bytes.NewReader(ciphertext), c, nonce, size)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, dr); err != nil {
			b.Fatal(err)
		}
	}
}

// gcx1 信封加密基准：AES-128-GCM 1MB 明文。
func BenchmarkEnvelopeEncrypt(b *testing.B) {
	const size = 1 * 1024 * 1024

	key := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		b.Fatal(err)
	}
	plain := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, plain); err != nil {
		b.Fatal(err)
	}

	b.SetBytes(size)

	for b.Loop() {
		if _, err := Encrypt(rootcrypto.AES128, key, plain); err != nil {
			b.Fatal(err)
		}
	}
}

// gcx1 信封解密基准：AES-128-GCM 1MB 明文。
func BenchmarkEnvelopeDecrypt(b *testing.B) {
	const size = 1 * 1024 * 1024

	key := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		b.Fatal(err)
	}
	plain := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, plain); err != nil {
		b.Fatal(err)
	}
	envelope, err := Encrypt(rootcrypto.AES128, key, plain)
	if err != nil {
		b.Fatal(err)
	}

	b.SetBytes(size)

	for b.Loop() {
		if _, err := Decrypt(key, envelope); err != nil {
			b.Fatal(err)
		}
	}
}

// errReader 始终返回指定错误的 Reader。
type errReader struct{ err error }

func (r *errReader) Read(p []byte) (int, error) { return 0, r.err }

// stuckReader 始终返回 (0, nil)，用于模拟底层 reader 空转（忙等防护测试）。
type stuckReader struct{}

func (r *stuckReader) Read(p []byte) (int, error) { return 0, nil }

// ==================== DecryptingReader 忙等防护 ====================

func TestDecryptingReader_NoProgress(t *testing.T) {
	dr, err := NewDecryptingReader(&stuckReader{}, mustCipher(t), testNonce(t), 0)
	assert.NoError(t, err)

	// totalSize=0 时首次 Read 即进入多余密文探测循环；
	// 底层 reader 持续 (0, nil) 空转，达到上限后必须返回 ErrNoProgress 而非死循环
	buf := make([]byte, 1024)
	_, err = dr.Read(buf)
	assert.ErrorIs(t, err, ErrNoProgress)

	// 回归：正常的空 reader（立即 EOF）应返回 io.EOF 而非忙等错误
	drOK, err := NewDecryptingReader(bytes.NewReader(nil), mustCipher(t), testNonce(t), 0)
	assert.NoError(t, err)
	_, err = drOK.Read(buf)
	assert.ErrorIs(t, err, io.EOF)
}

// ==================== NewEncryptingReader 无效 nonce ====================

func TestNewEncryptingReader_InvalidBaseNonce(t *testing.T) {
	c := mustCipher(t)
	_, err := NewEncryptingReader(bytes.NewReader(nil), c, []byte("short"), 0)
	assert.ErrorIs(t, err, ErrInvalidBaseNonce)
}

// ==================== NewDecryptingReader 无效 nonce ====================

func TestNewDecryptingReader_InvalidBaseNonce(t *testing.T) {
	c := mustCipher(t)
	_, err := NewDecryptingReader(bytes.NewReader(nil), c, []byte("short"), 0)
	assert.ErrorIs(t, err, ErrInvalidBaseNonce)
}

// ==================== EncryptingReader 空缓冲区 Read ====================

func TestEncryptingReader_EmptyBuffer(t *testing.T) {
	er, err := NewEncryptingReader(bytes.NewReader(nil), mustCipher(t), testNonce(t), 0)
	assert.NoError(t, err)

	n, err := er.Read([]byte{})
	assert.Equal(t, 0, n)
	assert.NoError(t, err)
}

// ==================== DecryptingReader 空缓冲区 Read ====================

func TestDecryptingReader_EmptyBuffer(t *testing.T) {
	dr, err := NewDecryptingReader(bytes.NewReader(nil), mustCipher(t), testNonce(t), 0)
	assert.NoError(t, err)

	n, err := dr.Read([]byte{})
	assert.Equal(t, 0, n)
	assert.NoError(t, err)
}

// ==================== EncryptingReader 缓存错误 ====================

func TestEncryptingReader_CachedError(t *testing.T) {
	testErr := errors.New("io error")
	er, err := NewEncryptingReader(&errReader{err: testErr}, mustCipher(t), testNonce(t), 100)
	assert.NoError(t, err)

	buf := make([]byte, 1024)
	_, err = er.Read(buf)
	assert.Error(t, err)

	// 第二次 Read 应返回缓存错误
	_, err = er.Read(buf)
	assert.ErrorIs(t, err, testErr)
}

// ==================== DecryptingReader 缓存错误 ====================

func TestDecryptingReader_CachedError(t *testing.T) {
	testErr := errors.New("io error")
	dr, err := NewDecryptingReader(&errReader{err: testErr}, mustCipher(t), testNonce(t), 100)
	assert.NoError(t, err)

	buf := make([]byte, 1024)
	_, err = dr.Read(buf)
	assert.Error(t, err)

	// 第二次 Read 应返回缓存错误
	_, err = dr.Read(buf)
	assert.ErrorIs(t, err, testErr)
}

// ==================== EncryptingReader nonce 溢出 ====================

func TestEncryptingReader_NonceOverflow(t *testing.T) {
	baseNonce := bytes.Repeat([]byte{0xFF}, blockNonceSize)
	plain := randBytes(t, ChunkSize+1) // 需要 2 块触发 blockIndex=1 溢出

	er, err := NewEncryptingReader(bytes.NewReader(plain), mustCipher(t), baseNonce, int64(len(plain)))
	assert.NoError(t, err)

	// 持续读取直到 nonce 溢出错误
	buf := make([]byte, 1024)
	for {
		_, readErr := er.Read(buf)
		if readErr != nil {
			assert.ErrorIs(t, readErr, ErrNonceOverflow)
			return
		}
	}
}

// ==================== EncryptingReader 读取错误（switch default）====================

func TestEncryptingReader_ReadError(t *testing.T) {
	testErr := errors.New("disk failure")
	er, err := NewEncryptingReader(&errReader{err: testErr}, mustCipher(t), testNonce(t), 100)
	assert.NoError(t, err)

	buf := make([]byte, 1024)
	_, err = er.Read(buf)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "disk failure")
}

// ==================== 负 totalSize 校验（自根包 crypto_test.go 迁入） ====================

func TestBlockAEAD_NegativeTotalSize(t *testing.T) {
	c, err := rootcrypto.NewCipher("AES", make([]byte, 16))
	require.NoError(t, err)

	_, err = NewEncryptingReader(bytes.NewReader(nil), c, make([]byte, 12), -1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "totalSize")

	_, err = NewDecryptingReader(bytes.NewReader(nil), c, make([]byte, 12), -1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "totalSize")

	// 非负 totalSize 不受影响
	r, err := NewEncryptingReader(bytes.NewReader(nil), c, make([]byte, 12), 0)
	require.NoError(t, err)
	assert.NotNil(t, r)
}

// ==================== totalSize 正向上界校验（int64 溢出防护） ====================

func TestBlockAEAD_TotalSizeTooLarge(t *testing.T) {
	c, err := rootcrypto.NewCipher("AES", make([]byte, 16))
	require.NoError(t, err)

	// totalSize 接近 MaxInt64 时 (totalSize + ChunkSize - 1) 会回绕为负，
	// 块数/长度计算错乱，构造阶段必须拒绝。
	_, err = NewEncryptingReader(bytes.NewReader(nil), c, make([]byte, 12), math.MaxInt64)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "totalSize too large")

	_, err = NewDecryptingReader(bytes.NewReader(nil), c, make([]byte, 12), math.MaxInt64)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "totalSize too large")

	// 上界边界值（MaxInt64-(ChunkSize-1)）本身合法，不触发回绕
	ok := int64(math.MaxInt64 - (ChunkSize - 1))
	er, err := NewEncryptingReader(bytes.NewReader(nil), c, make([]byte, 12), ok)
	require.NoError(t, err)
	assert.NotNil(t, er)
	dr, err := NewDecryptingReader(bytes.NewReader(nil), c, make([]byte, 12), ok)
	require.NoError(t, err)
	assert.NotNil(t, dr)
}

// ==================== EncryptingReader src 超长方向（实际字节数 > totalSize） ====================

// TestEncryptingReader_SourceLongerThanTotalSize src 提供的明文多于声明的
// totalSize：加密器按 totalSize 块结构输出，但实际读入超过声明长度，
// 结束时 readTotal != totalSize，必须返回 ErrSizeMismatch
// （密文已增量输出属预期行为，本测试只断言最终错误）。
func TestEncryptingReader_SourceLongerThanTotalSize(t *testing.T) {
	plain := randBytes(t, 1000) // 实际 1000 字节
	nonce := testNonce(t)

	er, err := NewEncryptingReader(bytes.NewReader(plain), mustCipher(t), nonce, 500)
	require.NoError(t, err)

	_, err = io.ReadAll(er)
	assert.ErrorIs(t, err, ErrSizeMismatch)
}

// ==================== 冻结格式黄金向量（KAT，Encrypt 方向） ====================
// fsb1 KAT 锚定冻结格式：固定 key/baseNonce/明文（5000 字节，跨 2 块）→
// 期望密文流固化为字面量常量。若实现输出的字节布局（块大小、tag 长度、
// nonce 派生、AAD 拼接、块序）任何一处漂移，KAT 断言即失败。
// 该 KAT 与 gcx1 的 KAT（envelope_test.go）共同构成格式冻结的独立锚点，
// 详见 doc.go 的冻结与 KAT 声明。
//
// 生成方法（一次性，随本测试固化，非运行时生成）：
//   - key = "0123456789abcdef"、SM4、baseNonce = 全零 12B。
//   - 明文 5000 字节（= 4096 + 904，跨块边界），plain[i] = byte(i)。
//   - 期望密文流 = 块0(CT 4096B || TAG 16B) || 块1(CT 904B || TAG 16B)，
//     共 5032 字节，以 hex 字面量固化。
const (
	fsb1KATKey   = "0123456789abcdef"
	fsb1KATNonce = "000000000000000000000000" // 全零 12B
	// fsb1 KAT 期望密文流 hex（5032 字节 = 10064 hex 字符，按 256 字节/行分段）。
	fsb1KATCiphertextHex = "61fcecf8e8c5ed9b94a07b719ca27c602f1a961c297e6c2ec2f3f934a04671f408a6eb43058e1f3ea70e807a70d19d15cd113ff66d62b1bfdead8d997fafca3c3eff92afc84731c33e33a960a571381d7b29ec5a145077df5a65a92168e8691bb2ae5e714386ee4962153a6fee6adeb438bb2556086a55656d1f66d7449f29bfc025492d9374b7ad3e44e0c18a7e777ad41bdafeb1598ef2085a4ca6b4b487befa02074852a10552526389e92904be1109b7db5b7f36c20391ee302e8e14dac92c55386f6b6bfdeb9d044351211e67d17dc1c507ceaee33e6e9deddcf1e5ffd77720d0d0c817223616c39885da95a748f11341a760cc9c5752d83ba6efb1aa9e453c9592218a3563e74a261dd25c2e0984a2f93b25c7245b69a5d4b3840715beec5abd80c6baa0f87fd6855919640ba3b09c664457b02762334161ee747b154351b9d0167c3e22717a344523795e3ff6dbe98fb7ed3d4657486484a01e1156b084e381115db40899a7ebea987f798e7bc887f0db37d369225dcacb6340c3518a6c56c927e555b0245bca96106cfa72454eb8f993f9a52aff6a1182264dd7ee61565c86842d029f1b0debca325b871602d7e4272e9809b752b5f439ecc79546cd42fafab416fd423a6b949923c05e3c8c2d7cd44cab61ef33a446181c84108e7b146f43aa1653a1a2fae16636e7eff515b741b774c036b8ea07e5ea152d1a66f43e59e2d82b029e6d0868f06ab366245579283a9370e5a0e51ed5570bccfab88f2510f80b7bf1916351e74981320c3990118dd16888db739b94687b01a908c1ea5a67bdb59a45a4ed2d82226528f6ecd34e771f564477eac6fb05de9636864b89fdfc426f1be335f5761206fb0bb7a3c922fc8166625acc9fc1974227591444c6974b4b741975f435dd6c4d1710ac23e26189d612b1d42dd2f565aec2bc280e107b914367e6364f34e4024259371b7f45c416dd1eb19222d05ac892301e36afa61513b0cf3b6bb6f156bd0ac86f872dc57524a93cc71679f8de22d4bbe682d68e1dccbef0d5c94ef227068a0565f598a6c0b9f4cbf7e7e4e280e2e5dc61b8f541ba2f1892184dc85b732545e8cd57dca9d3326ce12cc8330911d9ed3e3b3fe0960636bda873f78a40dd2b108ecd8471af1e61c53bd621492ae2928d84aa45daa0c9388108d1b43e26385b035f1d89c414254d58788c82b6d929217c86bb45a8a33752591d9093e37eb5f5755922641ad9de2d8e0c37d39ba20678f55d883f84444180409d6fff80e6c20577017018895dbe1b52eb3869b5fb8b0d98103b7338fba66bc61b7d1c9755698b6f310f62a541ed39a77589c372438b5313461148f378768c972968f071a69e9dce566d0d480453756cf1da1ba99cb086879db58a3b2de05205922cd30fc880f39d844ce97e67375ece4d58f7d93bac33aa2234e970f7601dc61e98eeaf94a2f1d8d5988b30db80f1863b7ad8c408ee29c63dc9690cc13427e35e35c7955ad44d23a3a77969a985114c2295fcb5c00e02c9b06fe0abc2e141f2f8ccc59e480a5d751fc188d136bf8fa839a4ade610e9bbd64d9fe944ff56d638903c487860c78c18d3f674058fb4b991db3f60b17ccdd14225e4c5374ca3acdf173dad12cbc8ac2287d4eed9b8dba0cd4f7ec3db44464812ee23ace7eb693f701dbcdbbbe55fe2a839e750e8bb17b5669711a07e28791f34bc8b4d4bdd59605e42982396882b8fc928746285cad7512eb2d933ec1213ebe74b6ac7b0239a6890253903f559b0ae3d78d964afa3a5e881922dfcd80e6ca1fa0865ce3749078e0bec3d4ed4abbe48935a70a69ac45d6cbb34d3f52bc31635c1a481094eba84d6c190029424c10fcfcdb276a682364b35c2c01816455f465ae77b4ad43f0442f76076ecae5845fb026ea950db164a6a74aed3674ff8bb0211b62ae6a8cc006056cd55e2082037a1496195986b6fb744ad789d07c742a6bc311b020a2bd5972db43f6ba12464f6b66a6f41fd0d8f851437901470efe93e0d4892be6e8da12e85953fcf26494d6c55451b1772dac67079e5efb75be4070237909781333806270c7e8a8b364d0e15c99b10d251bc6ec8cc052ab0b325f0cf7566f4143c20173cedd50fa305521aa224cd98556bdbf161815ee0a9f6777d78072c3f5c24a0266fca98625e18282eae6a25c9ba487214b97e567d2ca4fe5a76c4a880b057192c90163c6abba8827f6ae02b8fa98ce28850f8459552028e37b7039d7f8860ad5e595d0f98a259c570c7cb482fd11a8297f260b689fc77d0c4a0caa794a627b5a8690b427e2ae6a4f161ec1289b0a326be3518a83f44cb092b11696000c33e09e3002bcd70d613516787b8f907ceaa936b98f17a95ed19acb8841f9d3c4da21e8f593b67de42d479ff3629af6fc2a75e08e9171b47d34bfbe44e8481c4e3f25ece5ea97c01e948c42dbec9b106eac90e73cfcbc1db4c40c0aab4d3732d032e3db6ac04fea9e9ca0d2908a7ad142ec0a2eed4b56bbdddef51545454e67cac7459d8457cdf541f40dff416582f81dd347acabd04ae92f245b003cdfcd875939b964f8faca4134d1d4fe4bb91613056d76ef209bc506eed0224588248ad5ad1d51419d1dc54d197f86a9baf47127ec1cf20b9283a0c3a01796692faa5cbc00ecffe5c96fbaac6c5f4415f604508397f1389fafeb70acb7130005a1a562fe85f29d6d626e96cb003c845e6ca9a3e40237807a8d086b28d455206adbf3097e1a03ba1dd75a632f07dbaf71ded0a95b36bd5e44fc0cc08395cf823de5cbe03ee27f091ea7b8dac5d53021ec7ff132e10d88cfa60763fc45b83e9d2a8330d8af3f93e8d49cf539fa791729d11411d2b55bfa1430516ed9cd8baf7a88a1ab1f0ebeff477a8431dfec794299e1f15a27ce4f0f31759909614551cbbc5bb625d3f7c903c12f1a587c98b937567772832682a3edd85dc196cb3d6686f823a3aedcd7cb31b43a9770b60d3452e1edb8f27ef6f35ef6c5f11f8c02da578f4cbb54ab403b476191e4b7ca7fce8a624c257db5ab1655529353f59a1f0552a81c4a887c26ac7ce561638441ff9ed410f2c5c715766b724ce61b779f83d9b35c15609efc46897c4569bf63be499e2aabcac5f98ce933ccc28152096606ac643f829e65d8a7ec0134b751313b13e34f659896b3825b7c4167ef23a475f8ee27d0fa4d82ed9902420273640932c371a559e006a6f8fd21bb30620cb9aa5d00dd68cc135b0d007b4539d5dfee79ed2fcd18c86d70e8a8eb943cc116f2bdd6207e9fc6ecb7d678cae19ba2ce5bacaedc7348ec388b08993450014860534ef43a0c5e9d0791df0b1b007fa42990d2371b142ffbbac186eac9eb0b9f0b59bfa917dc725eeffe66fcc4c4aa15b102f3d35c94f43ed3f257c19ad1d2c52b315b682253440b4818126edce7dd31996b75466d93fec6f5e8c4a192492c865681809355083e0d2dee1162e7f82c86b4733fa2ac84780f815b03f871fbc10ab3a19f657a09386de680b4b640db8723e5935b624b7d39a235f796e7cab9e465ae0fbc49a8b597e5fd958af04383b9f8f68be6cb5a78be3a406c59457ebd8588c0d253eabaeaad28e63e798741185693d5b1aca8dd9464cc9cfd9f3b59cb18a7e49520541b272981176a58c602d81f67fe273d5056fd54e8a67b57e2e6daf5f3e4f638b0626a7a33a454b0c6c776adbe48e8999b80e8806d05cfad40eebcc7f504320959cdc57fdcdbe613b8c4661ab8d7d62c2a26bb7b7ab189915b678198458afef4dd7b73692661b8e58646968c1baf07ee771154365c732b2c74aadb57110a41f0b158ef67aa079b7d4cf7f42f01ba357811e5881782f3f23732d6265700e7fee977ad9b61411d125302cc262c55886c734e3c6ce822dad92c098c9847ed0a76802ecd729b57481c75db6f2da028ed13048756772aa081ed95a5092f80e19b38f3fdec479332dac78e0e7f36a0224d2f5f3c3a2e4e77bfea931c7b224aa2da0f86f20832fc3687fa04b1d3b03b3d07ddb6f59e86201867266eabbf18977ecbbf9355ba72cade5f6ca0f3028577f2974dd26e4fac5f74170a33da7812c932686010ac7735f349e3079319afec13a0c6f1d96f6959a2468b003e218624e847ac21c1d5f3973d8f35c9d5b62cae52740820990edbd85907d7efb591a4d111b917afa0928b03bb34f71dac630cdee42828aa932be489f841cf14154c922f1b6be3bf06daf8a59bd2bdf9dd6b72601ecf9c4fc3742adff0cadee0c51e328f61f218018307f0ea5c3b05eb0999a68f20532a7c9af63af4fb87f718aca0357507a710af87270004b42c653153379c0c25661b79da696eb7d0248f9a45c9a84ae3ec907d4d67a2919f253f70dfb37ed0f6f276ebe2d7878ba9b5049e10da46357d4657708b8107f05a7f2c1292358d1a0cb24c3d30b7295e4e4d96f3e0846512aa7469c305988110ea710e4d66c067a8c7e8f0e075eb33628d0d4c1d1d015364e25dfc64035ab009b65ad28def91c3de857aac6adc9d684bdf0b5ba6312487b91f04af003de86edfac1c0430476f7c80914d633061d0e77f43e81017a0c2222dc4e720e6d319ab5102a25cd1362f48cff7f4a96775dcd8cb82a8aad1becbba4d6e796e127a5fa199f97359d9b3547ec32257b76624cee15be9b20f5e0a8636207fe7d691b72b8e8e115883ab8142a71d38b0171c7cc04617b98e7f7a309569d46cfefee99e8202535fe5e204cbfc14cfae877bcbb9575f416aad095d5b11d2db6ed31e2a843c1de3bfffa24abbb6998aec772eeb64d8a83143f7aafc1755516b590de40ec9aa9b4faf59615b111bc81b82bffc4c1cc619652be65985ddada635bcd35d787737bec372254120f591253ef7982a2e9a495df09967d31860407a23dfd4a6ebf60d551b4f00f062ead64efb5d203a698bb09395250146b13fd558e3392dc56974e74ea5af3f34e8c2e63d4dff29d52cf8439283ce8def0a4a925d67c97920520b7d0e0106a31e1b28fd42d8f1417493f147e2bd07c0d1f2bbc8d9a624367eb3d928a751b17771ffa2f848f6fcd3e027b22c849a05f39d2eeb0e54adabe1258e72530bf7bf34c32bc9fe9e4715b283d29efbb52f3f80fb656bb62062d1e3d58c045a794d95d45b8ecfbe6ffa8a8b5f75fda120bb153fb67b756a0b1b9cb9ff34bdedccbf40a501a36dd2bd3f9adffe86422752aafd1c26934a732dc7105404a34105a729f4159f569d665763d0598742d3cad9e1aec005a6740fc4f13878a2e9035e46350e2d0e82b65b27d3e3420026b06729b9191bd3d6cf18da36255bfd44bfa384b59fc46ac8254b1579bb24cb1fe9ab4223fac4e343e416cd9b837a0b1a075a0fe789d6b1e2a452fd4c81745a60f4083bdbee589f5b34003e5001cdb3e87a5d7f574c252093abf16ef776f88023d280916ce8b5ca54400e7577b2c68c4f1996ab37e1cc51c56254b6ed8fae39d1c143d0f46881431720d5ba3702bf6cde26bf621ea6bb77a24259db0a1d7667685d78814d162c0ede3a2e016653c6a4fdd84b1af92f205c133027696ab5663dc853a14b9e747a53c841ae3a4d5ce1faff33f8909418dbdc49b4f0b775c7022b252f289d139d08b341d131e7ceeb739f568fe9dc9899d009ea0c31aa253b1095b22291195b393e09956f859a440b0a1cfa882c5257ed7f9b9ec285131ae13962bf754f54ed2ce15a599802bf815c1488eda066187f4d7357e5d5d2212cfab08c737c71990e04bc05272f942ed73d0d5b0505fcdfb951e62d2255b7cfd59463d90cd8eb6eaa572bbdb88ab69baba794ee430f7a3b8803cfea2d768f0c828525386a10c3a5fee17cade4a67b2a0f72f70a82ecd815a3f163b7e39ed2909393d4cc6685093f0a7f05be462c5c28e14f1e884ba30bdb66711c2a597a8fd0ac39be8cb7f1f84eb177ec231a352b15d8c2a8e1026716b8cfaecf6c90eab3fe324ac5580e01a213975226fc6d347505f60cc51d7035167b4a6bfd17b0101ba00858865675410293cc3bdb36f0ebab95d4624aeb85d15a802fc8273f22c8199e443e5d361db0000a8442f41e79b1b0c9b7957b219d5b69bd0f050aeb1df13360413d555a7c944f5c8fbf0af9d30240ab453f23f3a79a3893b54783838093f66dfdf28c75287ea3c2d030ae9b061f1377fc7845f6824e9f341c5ab05b584abbfd5d68f4f7fffa1c7fafe4db6daa6934a54a9fb3f0887bf488cafa3fe02a28b47b276b33738a3c132d653717ff30077d04146ce82f52fea426f472ebc521492da6e0e29035e041671b15b4da0b63b5c8cdeb684b31eb882cecb74b0178504a822ed8c490a13f1282c7fae7978fb171c0dfc46cc9406f1cc6f66f5c94f2d6304b6e35ae40d87dfa42d473e47a7fec783f0604d0aff8a437160b410daf34074039bd8d00105d1304e729598a304f6a4b67535d15337cc9c2ae8ea93efed3f17a94a6ba4847fc07c13cf4f53375b629803d986ddcf43c47d64c6c88774f73e9290963cfc6942d629ad922fec9f01e19012ee297cdfa59c92635a81687e5131913e12d413e924f52aff961e14d2051bce594f217df6d4f5e2fecc663f98d95dd2ee1ed50f1ecbed1560d8c8c43d906b1625c923969f501b89710e812d20580c05805ef7edeb92c38ffe410835b3e2e4df1b970b324934bf9426e809028717dd92dfd0ed8d56e95c8766a3179c903f8628869182098539465422529017d9eaba3567bda785938e75fcc365952cc8f619b5b13ecf337554b39802cfd67516b6cab30557918b87b07032d85815808786a0120433c3a7af235285e82c1fc289fcc7fc89bb82490baf1310ad3281b50222990e9278f4f02488637286e2b8857f40e02a49536700b2a0a42f011263b2f2af9daac4f33c2d671c38464cedfb336356a7cd0239e6fd317dca420d3e8b1d892d4bac23aab096df281587f4e250eb21bff362d05b18b7a01b3ce27b4d8537f05f865797c46c5a58c9df67e16412fc0f991a64a2cd3e61891510f67b4eea8ae5b86af3e5fcb7523a410a07589e9e173722398868276746e9572156697d25c0ac002e026a708cd0f4ee7d77fb480544617a77e95fbb6daec1decb0d77b133def180db"
)

// TestBlockAead_KAT_Encrypt fsb1 Encrypt 方向 KAT：固定参数下
// NewEncryptingReader 输出必须与固化常量逐字节一致。
func TestBlockAead_KAT_Encrypt(t *testing.T) {
	want, err := hex.DecodeString(fsb1KATCiphertextHex)
	require.NoError(t, err, "KAT hex 常量必须可解码")
	assert.Equal(t, 5000+2*TagSize, len(want), "KAT 密文长度应为 5000+2*16")

	nonce, err := hex.DecodeString(fsb1KATNonce)
	require.NoError(t, err, "KAT nonce 常量必须可解码")
	assert.Equal(t, blockNonceSize, len(nonce), "KAT baseNonce 应为 12 字节")

	// 重建固定明文 plain[i] = byte(i)，5000 字节（4096+904 两块）
	plain := make([]byte, 5000)
	for i := range plain {
		plain[i] = byte(i)
	}

	ct, err := encryptToBytes(t, plain, nonce, int64(len(plain)))
	require.NoError(t, err)
	assert.Equal(t, want, ct, "EncryptingReader 输出必须与冻结 KAT 一致")
}

// TestBlockAead_KAT_TamperAnyByte 篡改 fsb1 KAT 密文流任一字节，
// DecryptingReader 必须失败：密文/tag 字节被对应块的 GCM 认证拒绝。
func TestBlockAead_KAT_TamperAnyByte(t *testing.T) {
	ct, err := hex.DecodeString(fsb1KATCiphertextHex)
	require.NoError(t, err)
	nonce, err := hex.DecodeString(fsb1KATNonce)
	require.NoError(t, err)

	c, err := rootcrypto.NewCipher("SM4", []byte(fsb1KATKey))
	require.NoError(t, err)

	const plainLen = 5000
	for i := range ct {
		orig := ct[i]
		ct[i] = orig ^ 0xFF
		dr, err := NewDecryptingReader(bytes.NewReader(ct), c, nonce, plainLen)
		require.NoError(t, err)
		_, err = io.ReadAll(dr)
		assert.Error(t, err, "篡改字节 %d 应解密失败", i)
		ct[i] = orig
	}
}
