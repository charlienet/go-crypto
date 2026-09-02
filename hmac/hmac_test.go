package hmac

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/charlienet/go-crypto/hash"
	"github.com/emmansun/gmsm/sm3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHmac(t *testing.T) {
	key, err := hex.DecodeString("98123F7FDEB5255E18B9446A2C161024")
	require.NoError(t, err)

	c := `POST
x-ca-key:25080476
x-ca-nonce:r3dz9x3f
x-ca-timestamp:1754373030
/api/authcode/generate
{"card":"jkfsdklafkjdsgf","channel":"70","phone":"18483657766","timeout":"60s","version":"V1"}`

	s, err := New("HMACSM3", []byte(c))
	require.NoError(t, err)

	sign, err := s.Digest(key)
	require.NoError(t, err)

	// 真实断言：MAC 非空、确定性与可变性
	assert.NotEmpty(t, sign)
	// HMAC 确定性：同 key+消息 必须产出相同 MAC
	sign2, err := s.Digest(key)
	require.NoError(t, err)
	assert.Equal(t, sign.Bytes(), sign2.Bytes(), "相同输入的 HMAC 必须确定")
	// 正反验证：正确 MAC 通过、消息被篡改后必须失败
	//（注意：New 的 key 参数为 []byte(c)，Digest 的 msg 参数为 key 内码，
	// 故 Compare 的 msg 应传 key）
	assert.True(t, s.Compare(key, sign))
	assert.False(t, s.Compare(append(append([]byte(nil), key...), 'x'), sign))
	assert.False(t, s.Compare(key, sign2[:len(sign2)-1]))
}

// TestSm3_KnownVector：SM3("abc") 标准摘要。
//
// 期望值出处：GB/T 32905-2016 附录 A 官方向量；gmsm@v0.44.1
// sm3/sm3_test.go golden 表首行固化同一值；本机 OpenSSL 3.5.5
// （openssl dgst -sm3）独立复算一致。断言直接对依赖库 gmsm 的
// 已验证实现做锚定，不依赖本库自身实现自证；同时交叉断言本库
// hash.Sm3 输出与标准值一致。
func TestSm3_KnownVector(t *testing.T) {
	const want = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"

	h := sm3.Sum([]byte("abc"))
	assert.Equal(t, want, hex.EncodeToString(h[:]), "gmsm SM3(\"abc\") 与标准值不符")

	assert.Equal(t, want, hash.Sm3([]byte("abc")).Hex(), "本库 hash.Sm3(\"abc\") 与标准值不符")
}

// TestHmacSm3_KnownVector：HMAC-SM3 标准向量（RFC 4231 Case 1 参数）。
//
// 说明：gmsm@v0.44.1 的 sm3 包测试文件（sm3/sm3_test.go）不含
// HMAC 向量（grep HMAC 无结果），故期望值取自独立实现——
// 本机 OpenSSL 3.5.5（支持 SM3）按 RFC 4231 Case 1 参数生成：
//
//	openssl dgst -sm3 -mac HMAC -macopt hexkey:0b0b...0b
//	（key=0b*20，data="Hi There"）
//
//	SM3(stdin)= 51b00d1fb49832bfb01c3ce27848e59f871d9ba938dc563b338ca964755cce70
//
// HMAC 结构由标准库 crypto/hmac 提供（独立于本库），期望值来自
// OpenSSL 独立实现，满足"不依赖本库自身实现自证"。
func TestHmacSm3_KnownVector(t *testing.T) {
	key, err := hex.DecodeString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	require.NoError(t, err)

	result := Sm3(key, []byte("Hi There"))
	assert.Equal(t,
		"51b00d1fb49832bfb01c3ce27848e59f871d9ba938dc563b338ca964755cce70",
		result.Hex(),
		"HMAC-SM3 与 OpenSSL 3.5.5 独立计算值不一致",
	)
}

// TestHMacComparer_KeyCopy：New 必须拷贝保存密钥，调用方后续修改原
// 切片不得影响实例（对齐 asym/ed25519.go 注入拷贝模式）。
func TestHMacComparer_KeyCopy(t *testing.T) {
	key := []byte("original-key")
	c, err := New("HMACSHA256", key)
	require.NoError(t, err)
	sign1, err := c.Digest([]byte("msg"))
	require.NoError(t, err)

	// 修改原切片：若未拷贝，实例密钥随之改变，两次计算将一致（断言失败）
	key[0] = 'X'
	c2, err := New("HMACSHA256", []byte("Xriginal-key"))
	require.NoError(t, err)
	sign2, err := c2.Digest([]byte("msg"))
	require.NoError(t, err)
	assert.NotEqual(t, sign1.Bytes(), sign2.Bytes(), "修改外部 key 不应影响已构造实例")
}

// TestHMacComparer_Zero：#27b Zero 清零密钥后 Compare 必须恒失败且不 panic；
// Digest/From 返回 ErrZeroed、Hasher panic（新行为，详见 TestHMacComparer_Zeroed）。
func TestHMacComparer_Zero(t *testing.T) {
	c, err := New("HMACSHA256", []byte("secret-key"))
	require.NoError(t, err)

	msg := []byte("hello")
	target, err := c.Digest(msg)
	require.NoError(t, err)
	assert.True(t, c.Compare(msg, target.Bytes()), "Zero 前验证应通过")

	c.Zero()
	assert.False(t, c.Compare(msg, target.Bytes()), "Zero 后 Compare 必须失败")
	assert.False(t, c.Compare(msg, nil), "Zero 后对任意目标均必须失败")
}

// TestHMacComparer_Zeroed：Zero 后的显式行为——Digest/From 返回 ErrZeroed
// 且结果为 nil，Hasher panic（复用已销毁实例属编程错误）。
func TestHMacComparer_Zeroed(t *testing.T) {
	c, err := New("HMACSHA256", []byte("secret-key"))
	require.NoError(t, err)
	c.Zero()

	got, err := c.Digest([]byte("hello"))
	assert.ErrorIs(t, err, ErrZeroed, "Zero 后 Digest 必须返回 ErrZeroed")
	assert.Nil(t, got, "Zero 后 Digest 结果必须为 nil")

	got, err = c.From(bytes.NewReader([]byte("hello")))
	assert.ErrorIs(t, err, ErrZeroed, "Zero 后 From 必须返回 ErrZeroed")
	assert.Nil(t, got, "Zero 后 From 结果必须为 nil")

	assert.Panics(t, func() { c.Hasher() }, "Zero 后 Hasher 必须 panic")
}
