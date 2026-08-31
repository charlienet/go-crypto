package crypto_test

// D3 审核修复：低层不安全算法/模式闸门（P2#?）。
//
// 覆盖：
//   - 根包 NewCipher/GenerateKey：DES/3DES 默认拒绝 ErrInsecureAlgorithm，
//     WithInsecureAlgorithms() 放行（注册表 CipherFactory.Insecure 元数据驱动）
//   - symmetric.NewCipher（低层直达）：同闸门（supported 表 insecure 标记驱动）
//   - NewECB：默认拒绝，选项放行
//   - 协议层回归：由既有用例覆盖（executor_test.go / encryptor_test.go /
//     integration_test.go 均以 WithInsecureAlgorithms() 显式 opt-in 后往返通过；
//     协议层 prepare 闸门未因本项改动）。
//
// 错误判定统一走 ErrInsecureAlgorithm 哨兵（errors.Is 可识别）。

import (
	"errors"
	"testing"

	"github.com/charlienet/go-crypto"
	"github.com/charlienet/go-crypto/symmetric"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInsecureGate_NewCipher 根包 NewCipher 不安全算法闸门。
func TestInsecureGate_NewCipher(t *testing.T) {
	desKey := make([]byte, 8)

	// 默认拒绝：DES/3DES（含大小写别名归一）→ ErrInsecureAlgorithm
	for _, alg := range []string{"DES", "3DES", "3des"} {
		_, err := crypto.NewCipher(alg, desKey)
		assert.ErrorIs(t, err, crypto.ErrInsecureAlgorithm, "%s 默认应拒绝", alg)
	}

	// 放行：WithInsecureAlgorithms() 后可构造
	c, err := crypto.NewCipher("DES", desKey, crypto.WithInsecureAlgorithms())
	require.NoError(t, err, "WithInsecureAlgorithms 后 DES 应放行")
	assert.NotNil(t, c)
	_, err = crypto.NewCipher("3DES", make([]byte, 24), crypto.WithInsecureAlgorithms())
	require.NoError(t, err, "WithInsecureAlgorithms 后 3DES 应放行")

	// 放行后仍执行既有长度校验（闸门不吞掉密钥长度错误）
	_, err = crypto.NewCipher("DES", make([]byte, 7), crypto.WithInsecureAlgorithms())
	assert.Error(t, err, "DES 7B 密钥放行后仍应报错误")

	// 安全算法不受影响：AES/SM4 无闸门
	_, err = crypto.NewCipher("AES-128", make([]byte, 16))
	require.NoError(t, err)
	_, err = crypto.NewCipher("SM4", make([]byte, 16))
	require.NoError(t, err)
}

// TestInsecureGate_GenerateKey 根包 GenerateKey 不安全算法闸门。
func TestInsecureGate_GenerateKey(t *testing.T) {
	// 默认拒绝
	_, _, _, err := crypto.GenerateKey("DES")
	assert.ErrorIs(t, err, crypto.ErrInsecureAlgorithm, "GenerateKey(DES) 默认应拒绝")
	_, _, _, err = crypto.GenerateKey("3DES")
	assert.ErrorIs(t, err, crypto.ErrInsecureAlgorithm, "GenerateKey(3DES) 默认应拒绝")

	// 放行：生成合法长度的 key/iv/nonce（DES：8/8/12）
	key, iv, nonce, err := crypto.GenerateKey("DES", crypto.WithInsecureAlgorithms())
	require.NoError(t, err)
	assert.Len(t, key, 8)
	assert.Len(t, iv, 8)
	assert.Len(t, nonce, 12)

	// 安全算法不受影响
	key, iv, nonce, err = crypto.GenerateKey("AES-128")
	require.NoError(t, err)
	assert.Len(t, key, 16)
	assert.Len(t, iv, 16)
	assert.Len(t, nonce, 12)
}

// TestInsecureGate_ECB NewECB 不安全模式闸门（选项体系与 a/b 一致）。
func TestInsecureGate_ECB(t *testing.T) {
	c, err := crypto.NewCipher("AES-128", make([]byte, 16))
	require.NoError(t, err)

	// 默认拒绝
	_, err = c.NewECB()
	assert.ErrorIs(t, err, crypto.ErrInsecureAlgorithm, "NewECB 默认应拒绝")

	// 选项放行
	m, err := c.NewECB(crypto.WithInsecureAlgorithms())
	require.NoError(t, err)
	ct, err := m.Encrypt([]byte("hello world"))
	require.NoError(t, err)
	pt, err := m.Decrypt([]byte(ct))
	require.NoError(t, err)
	assert.Equal(t, "hello world", string(pt))
}

// TestInsecureGate_SymmetricDirect symmetric 子包低层直达 NewCipher 闸门。
func TestInsecureGate_SymmetricDirect(t *testing.T) {
	// 默认拒绝
	_, err := symmetric.NewCipher("DES", make([]byte, 8))
	assert.ErrorIs(t, err, crypto.ErrInsecureAlgorithm, "symmetric.NewCipher(DES) 默认应拒绝")

	// 泛名归一 + 闸门：大小写变体同样拒绝
	_, err = symmetric.NewCipher("3des", make([]byte, 24))
	assert.ErrorIs(t, err, crypto.ErrInsecureAlgorithm, "3des 归一后仍应拒绝")

	// 放行
	c, err := symmetric.NewCipher("DES", make([]byte, 8), symmetric.WithInsecureAlgorithms())
	require.NoError(t, err, "symmetric.NewCipher 放行后应构造成功")
	assert.NotNil(t, c)

	// 无闸门算法不受影响，泛名归一生效（"AES" → AES-128）
	_, err = symmetric.NewCipher("AES", make([]byte, 16))
	require.NoError(t, err)
}

// TestInsecureGate_ErrWrap 闸门错误可经 errors.Is 判定哨兵。
func TestInsecureGate_ErrWrap(t *testing.T) {
	_, err := crypto.NewCipher("DES", make([]byte, 8))
	require.Error(t, err)
	assert.True(t, errors.Is(err, crypto.ErrInsecureAlgorithm))
	_, _, _, err = crypto.GenerateKey("3DES")
	require.Error(t, err)
	assert.True(t, errors.Is(err, crypto.ErrInsecureAlgorithm))
}