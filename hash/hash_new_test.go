package hash

import (
	"bytes"
	"io"
	"sync"
	"testing"

	"github.com/charlienet/go-utils/bytex"
	"github.com/stretchr/testify/assert"
)

// cryptoCase 描述一个加密哈希的「一次性 / 流式纯函数」对照用例；
// 描述器的 Digest/From/Hasher 路径由 name 现场构造。
type cryptoCase struct {
	name       string
	oneShot    func(msg []byte) bytex.Bytes
	fromReader func(r io.Reader) (bytex.Bytes, error)
}

// allCryptoCases 返回 7 个加密哈希的对照表（键与注册表算法名一致）。
func allCryptoCases() []cryptoCase {
	return []cryptoCase{
		{"md5", Md5, Md5From},
		{"sha1", Sha1, Sha1From},
		{"sha224", Sha224, Sha224From},
		{"sha256", Sha256, Sha256From},
		{"sha384", Sha384, Sha384From},
		{"sha512", Sha512, Sha512From},
		{"sm3", Sm3, Sm3From},
	}
}

// TestHasherMatchesExistingAPIs 验证四方等价：
// New(name).Digest(msg) ≡ New(name).From(r) ≡ XxxFrom(r) ≡ Xxx(msg)，
// 另加 Hasher()+io.Copy 的增量路径；输入覆盖空、"hello world"、约 3KB。
func TestHasherMatchesExistingAPIs(t *testing.T) {
	datasets := [][]byte{
		{},
		[]byte("hello world"),
		bytes.Repeat([]byte("abc123"), 517), // 约 3KB，非整块长度
	}

	for _, tc := range allCryptoCases() {
		c, err := New(tc.name)
		assert.NoError(t, err, "%s", tc.name)
		for i, data := range datasets {
			want := tc.oneShot(data).Bytes()

			// 描述器一次性路径
			assert.Equal(t, want, c.Digest(data).Bytes(), "%s case %d Digest 不一致", tc.name, i)

			// 描述器流式路径
			from, err := c.From(bytes.NewReader(data))
			assert.NoError(t, err, "%s case %d", tc.name, i)
			assert.Equal(t, want, from.Bytes(), "%s case %d From 不一致", tc.name, i)

			// 纯函数流式路径
			streamed, err := tc.fromReader(bytes.NewReader(data))
			assert.NoError(t, err, "%s case %d", tc.name, i)
			assert.Equal(t, want, streamed.Bytes(), "%s case %d XxxFrom 不一致", tc.name, i)

			// 增量对象路径
			h := c.Hasher()
			_, err = io.Copy(h, bytes.NewReader(data))
			assert.NoError(t, err, "%s case %d", tc.name, i)
			assert.Equal(t, want, h.Sum(nil), "%s case %d Hasher 增量不一致", tc.name, i)
		}
	}
}

// TestHasherNameNormalization 验证 New/ByName 算法名大小写不敏感，
// 不支持的算法名返回错误，且错误保持哈希语义文案（哈希无公私密钥之分）。
func TestHasherNameNormalization(t *testing.T) {
	for _, name := range []string{"sha256", "SHA256", "ShA256"} {
		c, err := New(name)
		assert.NoError(t, err, "%q 应成功", name)
		assert.NotNil(t, c, "%q 应返回非 nil 描述器", name)

		fn, err := ByName(name)
		assert.NoError(t, err, "%q 应成功", name)
		assert.NotNil(t, fn, "%q 应返回非 nil 摘要函数", name)
	}

	// 非加密哈希与未知算法均不支持
	for _, name := range []string{"fnv32", "unknown"} {
		c, err := New(name)
		assert.Error(t, err, "%q 应返回错误", name)
		assert.Nil(t, c, "%q 出错时描述器应为 nil", name)
		assert.Contains(t, err.Error(), "unsupported hash function")

		fn, err := ByName(name)
		assert.Error(t, err, "%q 应返回错误", name)
		assert.Nil(t, fn, "%q 出错时摘要函数应为 nil", name)
		assert.Contains(t, err.Error(), "unsupported hash function")
	}
}

// TestHasherMultiWriterSameSource 验证 io.MultiWriter 组合两个 Hasher()
// 实例后，一次 io.Copy 即可同时得到 SHA-256 与 SM3 两个摘要，且与各自
// 独立读取同一份数据的 XxxFrom 结果一致。
func TestHasherMultiWriterSameSource(t *testing.T) {
	data := bytes.Repeat([]byte("dual-track"), 700) // 约 7KB

	c256, err := New("SHA256")
	assert.NoError(t, err)
	csm3, err := New("SM3")
	assert.NoError(t, err)
	h256, hsm3 := c256.Hasher(), csm3.Hasher()

	// 一次读取，同源写入两个哈希对象
	_, err = io.Copy(io.MultiWriter(h256, hsm3), bytes.NewReader(data))
	assert.NoError(t, err)

	// 与流式版本独立读取同一份数据的结果对照
	want256, err := Sha256From(bytes.NewReader(data))
	assert.NoError(t, err)
	assert.Equal(t, want256.Bytes(), h256.Sum(nil), "SHA-256 摘要不一致")

	wantSm3, err := Sm3From(bytes.NewReader(data))
	assert.NoError(t, err)
	assert.Equal(t, wantSm3.Bytes(), hsm3.Sum(nil), "SM3 摘要不一致")
}

// TestHasherReset 验证同一增量实例 Reset 后重新计算，结果等于对新数据的
// 独立计算，即状态被正确清空。
func TestHasherReset(t *testing.T) {
	first := []byte("first message")
	second := []byte("second message that is longer than the first one")

	c, err := New("SHA256")
	assert.NoError(t, err)
	h := c.Hasher()

	_, err = io.Copy(h, bytes.NewReader(first))
	assert.NoError(t, err)
	assert.Equal(t, Sha256(first).Bytes(), h.Sum(nil), "第一次计算结果不一致")

	// Reset 后写入新数据，须等于对新数据的独立计算
	h.Reset()
	_, err = io.Copy(h, bytes.NewReader(second))
	assert.NoError(t, err)
	assert.Equal(t, Sha256(second).Bytes(), h.Sum(nil), "Reset 后结果与独立计算不一致")
}

// TestHasherConcurrentIndependentInstances 验证多协程共享同一个描述器、
// 各自 Hasher() 取独立增量实例时，无数据竞争、结果一致（供 -race 覆盖）。
func TestHasherConcurrentIndependentInstances(t *testing.T) {
	const goroutines = 8
	data := bytes.Repeat([]byte("race-safe"), 400) // 约 3.6KB
	want := Sha256(data).Bytes()

	c, err := New("SHA256")
	assert.NoError(t, err) // 所有协程共享同一描述器：其本身无可变状态

	results := make([][]byte, goroutines) // 各协程只写自己的下标，无竞争
	// 带缓冲 channel：即使断言失败提前退出，后台协程也不会永久阻塞
	errCh := make(chan error, goroutines)

	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// 每协程经共享描述器派生独立实例，绝不共享 hash.Hash
			h := c.Hasher()
			if _, err := io.Copy(h, bytes.NewReader(data)); err != nil {
				errCh <- err
				return
			}
			results[i] = h.Sum(nil)
		}(i)
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		assert.NoError(t, err)
	}
	for i := 0; i < goroutines; i++ {
		assert.Equal(t, want, results[i], "goroutine %d 结果与一次性不一致", i)
	}
}

// TestHashComparerConcurrentSharedDescriptor 验证多协程并发调用共享描述器的
// Digest/Compare/From/Hasher 各方法，结果全部等于一次性基准（供 -race 覆盖）。
func TestHashComparerConcurrentSharedDescriptor(t *testing.T) {
	const goroutines = 8
	data := bytes.Repeat([]byte("shared-descriptor"), 300) // 约 5KB
	want := Sha256(data)

	c, err := New("SHA256")
	assert.NoError(t, err) // 描述器只读，可被所有协程安全共享

	digests := make([][]byte, goroutines) // 各协程只写自己的下标，无竞争
	// 带缓冲 channel：即使断言失败提前退出，后台协程也不会永久阻塞
	errCh := make(chan error, goroutines)

	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Digest 路径
			digests[i] = c.Digest(data).Bytes()
			// Compare 路径：正确摘要须为 true
			if !c.Compare(data, want.Bytes()) {
				errCh <- assert.AnError
				return
			}
			// From 路径
			from, err := c.From(bytes.NewReader(data))
			if err != nil {
				errCh <- err
				return
			}
			if !bytes.Equal(from.Bytes(), want.Bytes()) {
				errCh <- assert.AnError
			}
		}(i)
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		assert.NoError(t, err)
	}
	for i := 0; i < goroutines; i++ {
		assert.Equal(t, want.Bytes(), digests[i], "goroutine %d Digest 结果不一致", i)
	}
}
