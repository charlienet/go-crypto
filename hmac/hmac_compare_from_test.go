package hmac

import (
	"bytes"
	"errors"
	"math/rand"
	"sync"
	"testing"

	"github.com/charlienet/go-utils/bytex"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHMacComparerCompareFrom：流式 MAC 比较方法的完整行为矩阵——
// 全算法正确比对、篡改拒绝、错误传播、Zero 后报错（与 Compare 恒 false
// 的差异钉死）、与既有路径等价、共享描述器并发（供 -race）。
func TestHMacComparerCompareFrom(t *testing.T) {
	key := []byte("secret-key")

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

	// regName 为注册表键（New 查表用），oneShot 提供期望 MAC 基准。
	cases := []struct {
		regName string
		oneShot func(key, msg []byte) bytex.Bytes
	}{
		{"HMACMD5", Md5},
		{"HMACSHA1", Sha1},
		{"HMACSHA224", Sha224},
		{"HMACSHA256", Sha256},
		{"HMACSHA384", Sha384},
		{"HMACSHA512", Sha512},
		{"HMACSM3", Sm3},
	}

	// 1/2/5：全算法 × 多输入的正确比对、篡改拒绝、与 Compare 等价。
	for _, tc := range cases {
		for inputName, data := range inputs {
			t.Run(tc.regName+"/"+inputName, func(t *testing.T) {
				c, err := New(tc.regName, key)
				require.NoError(t, err)

				mac := tc.oneShot(key, data).Bytes()

				// 正确 MAC → true
				ok, err := c.CompareFrom(bytes.NewReader(data), mac)
				require.NoError(t, err)
				assert.True(t, ok, "正确 MAC 必须认证通过")

				// 与既有路径等价：CompareFrom(r, m) ≡ Compare(data, m)
				assert.Equal(t, c.Compare(data, mac), ok,
					"CompareFrom 必须与 Compare 结论一致")

				// 翻转 MAC 首/末字节 → false（MAC 长度由算法固定，恒 ≥16）
				first := append([]byte(nil), mac...)
				first[0] ^= 0xff
				ok, err = c.CompareFrom(bytes.NewReader(data), first)
				require.NoError(t, err)
				assert.False(t, ok, "首字节被篡改的 MAC 必须认证失败")

				last := append([]byte(nil), mac...)
				last[len(last)-1] ^= 0xff
				ok, err = c.CompareFrom(bytes.NewReader(data), last)
				require.NoError(t, err)
				assert.False(t, ok, "末字节被篡改的 MAC 必须认证失败")

				// 长度不足 / 超长 → false（走长度预检分支）
				ok, err = c.CompareFrom(bytes.NewReader(data), mac[:len(mac)-1])
				require.NoError(t, err)
				assert.False(t, ok, "长度不足的 MAC 必须认证失败")

				ok, err = c.CompareFrom(bytes.NewReader(data), append(append([]byte(nil), mac...), 0x00))
				require.NoError(t, err)
				assert.False(t, ok, "超长的 MAC 必须认证失败")
			})
		}
	}

	// 3：读取失败 → (false, err)，错误原样传播，布尔值不携带认证信息。
	t.Run("ErrorPropagation", func(t *testing.T) {
		wantErr := errors.New("read failed")
		c, err := New("HMACSHA256", key)
		require.NoError(t, err)

		mac := Sha256(key, []byte("hello world")).Bytes()
		ok, err := c.CompareFrom(&errReader{err: wantErr}, mac)
		require.Error(t, err)
		assert.True(t, errors.Is(err, wantErr), "底层读取错误必须原样传播")
		assert.False(t, ok)
	})

	// 4：Zero 后 → (false, ErrZeroed)，绝不退化为空密钥静默比较；
	// 同时钉住与 Compare（仅恒 false、无错误通道）的行为差异。
	t.Run("Zeroed", func(t *testing.T) {
		data := []byte("hello world")
		c, err := New("HMACSHA256", key)
		require.NoError(t, err)
		mac := Sha256(key, data).Bytes()

		ok, err := c.CompareFrom(bytes.NewReader(data), mac)
		require.NoError(t, err)
		require.True(t, ok, "Zero 前应认证通过")

		c.Zero()

		ok, err = c.CompareFrom(bytes.NewReader(data), mac)
		assert.ErrorIs(t, err, ErrZeroed, "Zero 后 CompareFrom 必须返回 ErrZeroed 而非静默比较")
		assert.False(t, ok)

		// 行为差异钉死：同一状态下 Compare 只返回 false、无错误可查。
		assert.False(t, c.Compare(data, mac), "Zero 后 Compare 恒 false")
	})

	// 6：多协程共享描述器并发 CompareFrom（各自独立 reader，供 -race）。
	t.Run("Concurrent", func(t *testing.T) {
		data := []byte("hello world")
		c, err := New("HMACSHA256", key)
		require.NoError(t, err)

		mac := Sha256(key, data).Bytes()
		badMac := append([]byte(nil), mac...)
		badMac[0] ^= 0xff

		const n = 8
		good := make([]bool, n) // 每个 goroutine 独占一个下标，无竞争
		bad := make([]bool, n)
		errs := make([]error, n)
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				// 正确 MAC：应认证通过且无错误
				ok, err := c.CompareFrom(bytes.NewReader(data), mac)
				good[i] = ok
				errs[i] = err
				// 篡改 MAC：应拒绝
				bad[i], _ = c.CompareFrom(bytes.NewReader(data), badMac)
			}(i)
		}
		wg.Wait()

		for i := 0; i < n; i++ {
			require.NoError(t, errs[i], "goroutine %d 并发 CompareFrom 不应报错", i)
			assert.True(t, good[i], "goroutine %d 正确 MAC 认证结果不一致", i)
			assert.False(t, bad[i], "goroutine %d 篡改 MAC 未被拒绝", i)
		}
	})
}
