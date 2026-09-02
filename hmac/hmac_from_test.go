package hmac

import (
	"bytes"
	"errors"
	"io"
	"math/rand"
	"testing"

	"github.com/charlienet/go-utils/bytex"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errReader 恒返回错误的读取器，用于验证流式接口的错误传播。
type errReader struct {
	err error
}

func (e *errReader) Read([]byte) (int, error) {
	return 0, e.err
}

// readerCases 返回全部 7 个 Reader 函数及其对应一次性版本的对照表。
func readerCases() []struct {
	name     string
	readerFn func(key []byte, r io.Reader) (bytex.Bytes, error)
	oneShot  func(key, msg []byte) bytex.Bytes
} {
	return []struct {
		name     string
		readerFn func(key []byte, r io.Reader) (bytex.Bytes, error)
		oneShot  func(key, msg []byte) bytex.Bytes
	}{
		{"Md5", Md5From, Md5},
		{"Sha1", Sha1From, Sha1},
		{"Sha224", Sha224From, Sha224},
		{"Sha256", Sha256From, Sha256},
		{"Sha384", Sha384From, Sha384},
		{"Sha512", Sha512From, Sha512},
		{"Sm3", Sm3From, Sm3},
	}
}

// TestHMacFromMatchesOneShot：全算法一致性，
// Reader 版本结果必须与对应一次性版本完全一致。
func TestHMacFromMatchesOneShot(t *testing.T) {
	key := []byte("secret-key")
	data := []byte("hello world")

	for _, tc := range readerCases() {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.readerFn(key, bytes.NewReader(data))
			require.NoError(t, err)
			assert.Equal(t, tc.oneShot(key, data).Bytes(), got.Bytes(),
				"Reader 版本必须与一次性版本结果一致")
		})
	}
}

// TestHMacFromLargeData：约 1MB 伪随机数据（固定 seed），
// 验证 Sha256From 分块读取与一次性 Sha256 结果一致。
func TestHMacFromLargeData(t *testing.T) {
	rnd := rand.New(rand.NewSource(42))
	data := make([]byte, 1024*1024)
	if _, err := rnd.Read(data); err != nil {
		t.Fatalf("生成伪随机数据失败: %v", err)
	}

	key := []byte("secret-key")
	got, err := Sha256From(key, bytes.NewReader(data))
	require.NoError(t, err)
	assert.Equal(t, Sha256(key, data).Bytes(), got.Bytes(),
		"1MB 数据下 Reader 版本必须与一次性版本结果一致")
}

// TestHMacFromErrorPropagation：底层 Reader 返回错误时，
// Reader 版本必须透传该错误且结果为 nil。
func TestHMacFromErrorPropagation(t *testing.T) {
	wantErr := errors.New("read failed")
	key := []byte("secret-key")

	cases := map[string]func(key []byte, r io.Reader) (bytex.Bytes, error){
		"Sha256From": Sha256From,
		"Sm3From":    Sm3From,
	}

	for name, fn := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := fn(key, &errReader{err: wantErr})
			require.Error(t, err)
			assert.True(t, errors.Is(err, wantErr), "错误必须原样传播")
			assert.Nil(t, got, "出错时结果必须为 nil")
		})
	}
}

// TestHMacFromEmptyInput：空输入下 Reader 版本与一次性版本结果一致。
func TestHMacFromEmptyInput(t *testing.T) {
	key := []byte("secret-key")

	for _, tc := range readerCases() {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.readerFn(key, bytes.NewReader(nil))
			require.NoError(t, err)
			assert.Equal(t, tc.oneShot(key, nil).Bytes(), got.Bytes(),
				"空输入下 Reader 版本必须与一次性版本结果一致")
		})
	}
}

// mutateReader 在首次 Read 时执行 mutate 回调（模拟 sumFrom 内部
// hmac.New 构造完成后、流式读取过程中调用方篡改原 key 切片），
// 随后透传底层数据。
type mutateReader struct {
	src    io.Reader
	mutate func()
	done   bool
}

func (m *mutateReader) Read(p []byte) (int, error) {
	if !m.done {
		m.done = true
		m.mutate()
	}
	return m.src.Read(p)
}

// TestHMacFromKeyCopy：sumFrom 构造 HMAC 对象后（流式读取中途）
// 修改原 key 切片，Reader 结果必须与用原始 key 的一次性结果一致
// （对齐现有测试对密钥拷贝语义的关注：hmac.New 内部即时拷贝密钥）。
func TestHMacFromKeyCopy(t *testing.T) {
	key := []byte("secret-key")
	orig := append([]byte(nil), key...)
	data := []byte("hello world")

	r := &mutateReader{
		src: bytes.NewReader(data),
		mutate: func() {
			for i := range key {
				key[i] = 0xFF
			}
		},
	}

	got, err := Sha256From(key, r)
	require.NoError(t, err)
	assert.Equal(t, Sha256(orig, data).Bytes(), got.Bytes(),
		"流式读取中途篡改原 key 不应影响结果（密钥须在构造时拷贝）")
}
