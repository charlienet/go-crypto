package hmac

import (
	"bytes"
	"crypto/sha256"
	"io"
	"math/rand"
	"sync"
	"testing"

	"github.com/charlienet/go-utils/bytex"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHasherMatchesAllAPIs：全算法等价性——HMacComparer 的 Digest、From、
// Hasher 增量（io.Copy）三条实例路径，必须与包级流式 XxxFrom、一次性 Xxx
// 全部一致；覆盖 7 算法 × 空 / "hello world" / 约 3KB 输入。
func TestHasherMatchesAllAPIs(t *testing.T) {
	rnd := rand.New(rand.NewSource(7))
	mid := make([]byte, 3072)
	if _, err := rnd.Read(mid); err != nil {
		t.Fatalf("生成伪随机数据失败: %v", err)
	}
	inputs := map[string][]byte{
		"empty": {},
		"short": []byte("hello world"),
		"3KB":   mid,
	}

	key := []byte("secret-key")
	cases := []struct {
		regName string
		oneShot func(key, msg []byte) bytex.Bytes
		fromFn  func(key []byte, r io.Reader) (bytex.Bytes, error)
	}{
		{"HMACMD5", Md5, Md5From},
		{"HMACSHA1", Sha1, Sha1From},
		{"HMACSHA224", Sha224, Sha224From},
		{"HMACSHA256", Sha256, Sha256From},
		{"HMACSHA384", Sha384, Sha384From},
		{"HMACSHA512", Sha512, Sha512From},
		{"HMACSM3", Sm3, Sm3From},
	}

	for _, tc := range cases {
		for inputName, data := range inputs {
			t.Run(tc.regName+"/"+inputName, func(t *testing.T) {
				// 一次性包级函数为基准
				want := tc.oneShot(key, data).Bytes()

				// 流式包级函数
				got, err := tc.fromFn(key, bytes.NewReader(data))
				require.NoError(t, err)
				assert.Equal(t, want, got.Bytes(), "XxxFrom 必须与一次性版本一致")

				c, err := New(tc.regName, key)
				require.NoError(t, err)

				// 描述器一次性入口
				dig, err := c.Digest(data)
				require.NoError(t, err)
				assert.Equal(t, want, dig.Bytes(), "Digest 必须与一次性版本一致")

				// 描述器流式入口
				frm, err := c.From(bytes.NewReader(data))
				require.NoError(t, err)
				assert.Equal(t, want, frm.Bytes(), "From 必须与一次性版本一致")

				// 描述器增量入口（Hasher + io.Copy）
				h := c.Hasher()
				n, err := io.Copy(h, bytes.NewReader(data))
				require.NoError(t, err)
				require.EqualValues(t, len(data), n)
				assert.Equal(t, want, h.Sum(nil), "Hasher 增量结果必须与一次性版本一致")
			})
		}
	}
}

// TestHasherNameNormalization：算法名大小写不敏感（New + Hasher 链路）；
// 未知算法（含缺少 HMAC 前缀）返回错误且实例为 nil。
func TestHasherNameNormalization(t *testing.T) {
	key := []byte("k")

	for _, name := range []string{"HMACSHA256", "hmacsha256", "HmacSha256"} {
		c, err := New(name, key)
		require.NoError(t, err, name)
		require.NotNil(t, c, name)
		assert.NotNil(t, c.Hasher(), name)
	}

	for _, name := range []string{"sha256", "unknown", ""} {
		c, err := New(name, key)
		assert.ErrorContains(t, err, "unsupported HMAC function", name)
		assert.Nil(t, c, name)
	}
}

// TestHasherMultiWriterSinglePass：io.MultiWriter 组合 Hasher() 与标准库
// SHA-256，一次 io.Copy 同时得到摘要与 MAC，两者分别与标准库摘要、
// 一次性/流式接口结果一致（同源一次读取的核心动机）。
func TestHasherMultiWriterSinglePass(t *testing.T) {
	key := []byte("secret-key")
	data := []byte("hello world")

	c, err := New("HMACSHA256", key)
	require.NoError(t, err)

	digest := sha256.New()
	mac := c.Hasher()

	n, err := io.Copy(io.MultiWriter(digest, mac), bytes.NewReader(data))
	require.NoError(t, err)
	require.EqualValues(t, len(data), n)

	wantSum := sha256.Sum256(data)
	assert.Equal(t, wantSum[:], digest.Sum(nil), "摘要须与标准库 SHA-256 一致")

	from, err := Sha256From(key, bytes.NewReader(data))
	require.NoError(t, err)
	assert.Equal(t, Sha256(key, data).Bytes(), mac.Sum(nil),
		"MAC 须与一次性版本一致")
	assert.Equal(t, from.Bytes(), mac.Sum(nil),
		"MAC 须与流式版本一致")
}

// TestHasherKeyLifecycle：New 拷贝密钥、Hasher 构造增量对象后清零原 key
// 切片，两条路径（Hasher 增量 / Digest 一次性）结果仍须与用原始 key 的
// 一次性结果一致——实证标准库 hmac.New 构造时拷贝派生密钥、HMacComparer
// 持有独立副本。
func TestHasherKeyLifecycle(t *testing.T) {
	key := []byte("secret-key")
	orig := append([]byte(nil), key...)
	data := []byte("hello world")

	c, err := New("HMACSHA256", key)
	require.NoError(t, err)
	h := c.Hasher()

	// 构造完成后立刻清零原 key（bytes.Fill 非标准库函数，用循环置零）
	for i := range key {
		key[i] = 0
	}

	_, err = h.Write(data)
	require.NoError(t, err)
	want := Sha256(orig, data).Bytes()
	assert.Equal(t, want, h.Sum(nil),
		"密钥已在构造时派生进内部状态，清零原切片不应影响 Hasher 结果")

	dig, err := c.Digest(data)
	require.NoError(t, err)
	assert.Equal(t, want, dig.Bytes(),
		"HMacComparer 持有密钥副本，清零调用方切片不应影响 Digest 结果")
}

// TestHasherConcurrentSharedComparer（供 -race）：多协程共享同一
// *HMacComparer，各自 Hasher() 派生独立增量对象写同一数据、各自
// Digest/Compare，结果全部一致。
func TestHasherConcurrentSharedComparer(t *testing.T) {
	key := []byte("secret-key")
	data := []byte("hello world")
	want := Sha256(key, data).Bytes()

	c, err := New("HMACSHA256", key)
	require.NoError(t, err)

	const n = 8
	results := make([][]byte, n) // 每个 goroutine 独占一个下标，无竞争
	oks := make([]bool, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// 各自派生独立增量对象（Hasher 返回对象非并发安全，但每协程
			// 独立实例 + 共享只读描述器是安全的）
			h := c.Hasher()
			if _, err := h.Write(data); err != nil {
				return // 结果留 nil，由下方断言捕获
			}
			results[i] = h.Sum(nil)

			dig, err := c.Digest(data)
			oks[i] = err == nil &&
				bytes.Equal(dig.Bytes(), want) &&
				c.Compare(data, want)
		}(i)
	}
	wg.Wait()

	for i := 0; i < n; i++ {
		require.NotNil(t, results[i], "goroutine %d Hasher 计算失败", i)
		assert.Equal(t, want, results[i], "goroutine %d Hasher 结果不一致", i)
		assert.True(t, oks[i], "goroutine %d Digest/Compare 结果不一致", i)
	}
}

// TestConcurrentFromAndComparer：多协程并发调用纯函数接口
// Sha256From（各自独立 Reader）与共享只读实例的 HMacComparer.Compare
// （供 -race），结果须稳定一致。
func TestConcurrentFromAndComparer(t *testing.T) {
	key := []byte("secret-key")
	data := []byte("hello world")
	want := Sha256(key, data).Bytes()

	comparer, err := New("HMACSHA256", key)
	require.NoError(t, err)
	sig, err := comparer.Digest(data)
	require.NoError(t, err)

	const n = 8
	fromResults := make([][]byte, n) // 每个 goroutine 独占一个下标，无竞争
	verifyResults := make([]bool, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			got, err := Sha256From(key, bytes.NewReader(data))
			if err == nil {
				fromResults[i] = got.Bytes()
			}
			verifyResults[i] = comparer.Compare(data, sig)
		}(i)
	}
	wg.Wait()

	for i := 0; i < n; i++ {
		assert.Equal(t, want, fromResults[i], "goroutine %d Sha256From 结果不一致", i)
		assert.True(t, verifyResults[i], "goroutine %d Compare 结果不稳定", i)
	}
}
