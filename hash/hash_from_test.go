package hash

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"sync"
	"testing"

	"github.com/charlienet/go-utils/bytex"
	"github.com/spaolacci/murmur3"
	"github.com/stretchr/testify/assert"
)

// readerCase 描述一对「Reader 版本 / 一次性版本」的等价性测试用例。
// 各函数返回类型不一（bytex.Bytes / []byte / uint64 / uint32），
// 统一经 fmt 规范化为可比较的字符串表示。
type readerCase struct {
	name string
	// oneShot 一次性计算，返回值原样交给 normalize 比较。
	oneShot func(msg []byte) any
	// viaReader 流式计算，返回值原样交给 normalize 比较。
	viaReader func(r io.Reader) (any, error)
}

// normalize 将不同类型的哈希结果统一为可比较的字符串。
func normalize(v any) string {
	switch x := v.(type) {
	case bytex.Bytes:
		return fmt.Sprintf("%x", x.Bytes())
	case []byte:
		return fmt.Sprintf("%x", x)
	default:
		return fmt.Sprintf("%v", x)
	}
}

// allReaderCases 返回全部 12 个 Reader 函数的等价性测试用例表。
func allReaderCases() []readerCase {
	return []readerCase{
		{"Md5", func(m []byte) any { return Md5(m) },
			func(r io.Reader) (any, error) { return Md5From(r) }},
		{"Sha1", func(m []byte) any { return Sha1(m) },
			func(r io.Reader) (any, error) { return Sha1From(r) }},
		{"Sha224", func(m []byte) any { return Sha224(m) },
			func(r io.Reader) (any, error) { return Sha224From(r) }},
		{"Sha256", func(m []byte) any { return Sha256(m) },
			func(r io.Reader) (any, error) { return Sha256From(r) }},
		{"Sha384", func(m []byte) any { return Sha384(m) },
			func(r io.Reader) (any, error) { return Sha384From(r) }},
		{"Sha512", func(m []byte) any { return Sha512(m) },
			func(r io.Reader) (any, error) { return Sha512From(r) }},
		{"Sm3", func(m []byte) any { return Sm3(m) },
			func(r io.Reader) (any, error) { return Sm3From(r) }},
		{"Murmur3", func(m []byte) any { return Murmur3(m) },
			func(r io.Reader) (any, error) { return Murmur3From(r) }},
		{"XXhash", func(m []byte) any { return XXhash(m) },
			func(r io.Reader) (any, error) { return XXhashFrom(r) }},
		{"XXHashUint64", func(m []byte) any { return XXHashUint64(m) },
			func(r io.Reader) (any, error) { return XXHashUint64From(r) }},
		{"Fnv32", func(m []byte) any { return Fnv32(m) },
			func(r io.Reader) (any, error) { return Fnv32From(r) }},
		{"Fnv64", func(m []byte) any { return Fnv64(m) },
			func(r io.Reader) (any, error) { return Fnv64From(r) }},
	}
}

// TestHashFromMatchesOneShot 验证全部 Reader 版本与一次性版本结果一致。
func TestHashFromMatchesOneShot(t *testing.T) {
	datasets := [][]byte{
		[]byte("hello world"),
		{},
		bytes.Repeat([]byte("abc123"), 517), // 非整块长度，跨多个 io.Copy 缓冲
	}

	for _, tc := range allReaderCases() {
		for i, data := range datasets {
			got, err := tc.viaReader(bytes.NewReader(data))
			assert.NoError(t, err, "%s case %d", tc.name, i)
			assert.Equal(t, normalize(tc.oneShot(data)), normalize(got),
				"%s case %d 与一次性版本不一致", tc.name, i)
		}
	}
}

// TestHashFromLargeData 验证约 1MB 数据下 Reader 版本与一次性版本一致。
func TestHashFromLargeData(t *testing.T) {
	rng := rand.New(rand.NewSource(42)) // 固定 seed 保证可重复
	data := make([]byte, 1024*1024)
	rng.Read(data)

	// SHA-256：摘要一致
	want256 := Sha256(data)
	got256, err := Sha256From(bytes.NewReader(data))
	assert.NoError(t, err)
	assert.Equal(t, want256.Bytes(), got256.Bytes())

	// Murmur3：64 位整型一致（同时与第三方库直接结果对照）
	wantM, err := Murmur3From(bytes.NewReader(data))
	assert.NoError(t, err)
	assert.Equal(t, murmur3.Sum64(data), wantM)
	assert.Equal(t, Murmur3(data), wantM)

	// XXHash：64 位整型一致
	wantX, err := XXHashUint64From(bytes.NewReader(data))
	assert.NoError(t, err)
	assert.Equal(t, XXHashUint64(data), wantX)
}

// errReader 总是返回错误的读取源，用于验证错误传播。
type errReader struct {
	err error
}

func (e *errReader) Read(p []byte) (int, error) {
	return 0, e.err
}

// TestHashFromErrorPropagation 验证底层读取错误能传播到每个 Reader 函数，
// 且返回结果为 nil/零值。
func TestHashFromErrorPropagation(t *testing.T) {
	sentinel := assert.AnError

	// 返回 bytex.Bytes 的 7 个函数
	byteFuncs := map[string]func(io.Reader) (bytex.Bytes, error){
		"Md5From":    Md5From,
		"Sha1From":   Sha1From,
		"Sha224From": Sha224From,
		"Sha256From": Sha256From,
		"Sha384From": Sha384From,
		"Sha512From": Sha512From,
		"Sm3From":    Sm3From,
	}
	for name, f := range byteFuncs {
		got, err := f(&errReader{err: sentinel})
		assert.ErrorIs(t, err, sentinel, "%s 应传播错误", name)
		assert.Nil(t, got, "%s 出错时结果应为 nil", name)
	}

	// 返回 []byte 的 XXhashFrom
	xgot, err := XXhashFrom(&errReader{err: sentinel})
	assert.ErrorIs(t, err, sentinel)
	assert.Nil(t, xgot)

	// 返回 uint64 的函数
	u64Funcs := map[string]func(io.Reader) (uint64, error){
		"Murmur3From":      Murmur3From,
		"XXHashUint64From": XXHashUint64From,
		"Fnv64From":        Fnv64From,
	}
	for name, f := range u64Funcs {
		got, err := f(&errReader{err: sentinel})
		assert.ErrorIs(t, err, sentinel, "%s 应传播错误", name)
		assert.Zero(t, got, "%s 出错时结果应为零值", name)
	}

	// 返回 uint32 的 Fnv32From
	got32, err := Fnv32From(&errReader{err: sentinel})
	assert.ErrorIs(t, err, sentinel)
	assert.Zero(t, got32)
}

// TestHashFromEmptyInput 验证空输入下 Reader 版本与一次性版本一致。
func TestHashFromEmptyInput(t *testing.T) {
	for _, tc := range allReaderCases() {
		got, err := tc.viaReader(bytes.NewReader(nil))
		assert.NoError(t, err, "%s", tc.name)
		assert.Equal(t, normalize(tc.oneShot(nil)), normalize(got), "%s 空输入结果不一致", tc.name)
	}
}

// TestHashComparerCompareFrom 表驱动验证描述器流式比较方法 CompareFrom：
// 正确摘要 / 篡改摘要 / 读取错误传播 / 与 Compare 等价 / 并发共享描述器。
func TestHashComparerCompareFrom(t *testing.T) {
	datasets := [][]byte{
		{},
		[]byte("hello world"),
		bytes.Repeat([]byte("abc123"), 517), // 约 3KB，跨 io.Copy 缓冲边界
	}

	// 1. 正确摘要 → true：7 个加密哈希 × 3 种输入
	for _, cc := range allCryptoCases() {
		c, err := New(cc.name)
		assert.NoError(t, err, "%s", cc.name)
		for i, data := range datasets {
			ok, err := c.CompareFrom(bytes.NewReader(data), cc.oneShot(data).Bytes())
			assert.NoError(t, err, "%s case %d", cc.name, i)
			assert.True(t, ok, "%s case %d 正确摘要应返回 true", cc.name, i)
		}
	}

	// 2. 篡改摘要 → false：翻转首/末字节、长度不足、长度超长
	t.Run("TamperedTargets", func(t *testing.T) {
		data := []byte("hello world")
		cases := []struct {
			desc   string
			mutate func(want []byte) []byte
			wantOk bool
		}{
			// 空摘要无字节可翻转，跳过翻转用例
			{"首字节翻转", func(w []byte) []byte { b := append([]byte{}, w...); b[0] ^= 0xff; return b }, false},
			{"末字节翻转", func(w []byte) []byte { b := append([]byte{}, w...); b[len(b)-1] ^= 0xff; return b }, false},
			{"长度不足（截断）", func(w []byte) []byte { return w[:len(w)-1] }, false},
			{"长度超长（追加）", func(w []byte) []byte { return append(append([]byte{}, w...), 0x00) }, false},
		}
		for _, cc := range allCryptoCases() {
			c, err := New(cc.name)
			assert.NoError(t, err)
			want := cc.oneShot(data).Bytes()
			if len(want) == 0 {
				continue
			}
			for _, tc := range cases {
				ok, err := c.CompareFrom(bytes.NewReader(data), tc.mutate(want))
				assert.NoError(t, err, "%s %s", cc.name, tc.desc)
				assert.Equal(t, tc.wantOk, ok, "%s %s 应返回 %v", cc.name, tc.desc, tc.wantOk)
			}
			// 长度预检路径：空 target 与非空摘要长度不等，须 false 且不进入常量时间比较
			ok, err := c.CompareFrom(bytes.NewReader(data), nil)
			assert.NoError(t, err, "%s 空 target", cc.name)
			assert.False(t, ok, "%s 空 target 应返回 false", cc.name)
		}
	})

	// 3. 错误传播：读取失败时返回 (false, err)，布尔值不携带校验信息
	sentinel := assert.AnError
	for _, cc := range allCryptoCases() {
		c, err := New(cc.name)
		assert.NoError(t, err)
		ok, err := c.CompareFrom(&errReader{err: sentinel}, []byte("whatever"))
		assert.Error(t, err, "%s 应传播读取错误", cc.name)
		assert.True(t, errors.Is(err, sentinel), "%s 错误应为哨兵错误", cc.name)
		assert.False(t, ok, "%s 出错时布尔值须为 false", cc.name)
	}

	// 4. 与 Compare 等价：同一数据不同载体（[]byte vs io.Reader），含篡改 target
	{
		data := []byte("hello world")
		c, err := New("sha256")
		assert.NoError(t, err)
		want := Sha256(data).Bytes()
		targets := [][]byte{
			want,
			{0x01, 0x02},                         // 长度不足
			append(append([]byte{}, want...), 0), // 长度超长
			nil,
		}
		for i, target := range targets {
			viaReader, err := c.CompareFrom(bytes.NewReader(data), target)
			assert.NoError(t, err, "case %d", i)
			assert.Equal(t, c.Compare(data, target), viaReader, "case %d CompareFrom 与 Compare 不一致", i)
		}
	}

	// 5. 并发：多协程共享同一描述器并发 CompareFrom（各自独立 reader），
	// 结果全部一致（供 -race 覆盖）
	{
		const goroutines = 8
		data := bytes.Repeat([]byte("concurrent-compare"), 300) // 约 4.8KB
		c, err := New("sha256")
		assert.NoError(t, err)
		target := Sha256(data).Bytes()

		oks := make([]bool, goroutines) // 各协程只写自己的下标，无竞争
		// 带缓冲 channel：即使断言失败提前退出，后台协程也不会永久阻塞
		errCh := make(chan error, goroutines)

		var wg sync.WaitGroup
		for i := 0; i < goroutines; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				ok, err := c.CompareFrom(bytes.NewReader(data), target)
				if err != nil {
					errCh <- err
					return
				}
				oks[i] = ok
			}(i)
		}
		wg.Wait()
		close(errCh)

		for err := range errCh {
			assert.NoError(t, err)
		}
		for i := 0; i < goroutines; i++ {
			assert.True(t, oks[i], "goroutine %d 结果应为 true", i)
		}
	}
}
