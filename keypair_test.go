package crypto_test

import (
	"crypto/rsa"
	"encoding/json"
	"testing"

	"github.com/emmansun/gmsm/sm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/charlienet/go-crypto"
	_ "github.com/charlienet/go-crypto/keymgr" // 注册密钥对生成器（GenerateKeyPair 协议入口依赖）
)

// --- Reset 测试 ---

func TestKeyPair_Reset(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair(crypto.RSA)
	assert.NotNil(t, kp.PrivateKey)
	assert.NotNil(t, kp.PublicKey)

	kp.Reset()
	assert.Nil(t, kp.PrivateKey)
	assert.Nil(t, kp.PublicKey)
}

func TestKeyPair_Reset_AllTypes(t *testing.T) {
	algorithms := []crypto.AsymmetricAlgorithm{crypto.RSA, crypto.SM2, crypto.ECDSA, crypto.ED25519}

	for _, algo := range algorithms {
		kp, err := crypto.GenerateKeyPair(algo)
		require.NoError(t, err)

		kp.Reset()
		assert.Nil(t, kp.PrivateKey, "algorithm=%s", algo)
		assert.Nil(t, kp.PublicKey, "algorithm=%s", algo)
	}
}

// --- 序列化禁止测试 ---

func TestKeyPair_MarshalJSON_Forbidden(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair(crypto.RSA)

	_, err := kp.MarshalJSON()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "serialization is disabled")
}

func TestKeyPair_UnmarshalJSON_Forbidden(t *testing.T) {
	kp := &crypto.KeyPair{}

	err := kp.UnmarshalJSON([]byte("{}"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "deserialization is disabled")
}

// --- JSON 序列化绕过防护测试（P0 安全修复） ---

func TestKeyPair_JSONBypass(t *testing.T) {
	kp, err := crypto.GenerateKeyPair(crypto.RSA)
	require.NoError(t, err)

	// 值类型放入 map：map 元素不可寻址，绕过指针接收者 MarshalJSON
	// 修复前会完整输出 RSA 私钥（含 Primes、D 等字段）
	data, err := json.Marshal(map[string]crypto.KeyPair{"k": *kp})
	require.NoError(t, err)
	assert.NotContains(t, string(data), "Primes")
	assert.NotContains(t, string(data), "D")

	// 值类型直接作为 interface{} 传入：reflect.ValueOf 返回不可寻址值，同样绕过
	data, err = json.Marshal(any(*kp))
	require.NoError(t, err)
	assert.NotContains(t, string(data), "Primes")
	assert.NotContains(t, string(data), "D")
}

// --- 密钥清零覆盖测试（P1 A1） ---

func TestKeyPair_Reset_SM2Zeroed(t *testing.T) {
	kp, err := crypto.GenerateKeyPair(crypto.SM2)
	require.NoError(t, err)

	// Reset 前保存私钥引用（Reset 会将 kp.PrivateKey 置 nil）
	priv := kp.PrivateKey.(*sm2.PrivateKey)
	require.NotNil(t, priv)
	assert.NotEmpty(t, priv.D.Bytes(), "生成后 SM2 私钥 D 不应为零")

	kp.Reset()

	// sm2.PrivateKey 嵌入 ecdsa.PrivateKey，D 底层内存应被清零
	// 注：Sign()/BitLen() 只检查 len(abs) 不能反映清零状态，须断言 Bytes() 全零
	assert.Empty(t, priv.D.Bytes(), "Reset 后 SM2 私钥 D 应被清零")
}

func TestKeyPair_Reset_RSAZeroed(t *testing.T) {
	kp, err := crypto.GenerateKeyPair(crypto.RSA)
	require.NoError(t, err)

	priv := kp.PrivateKey.(*rsa.PrivateKey)
	require.NotNil(t, priv)

	// 先 Precompute 填充 CRT 预计算参数，否则 Dp/Dq/Qinv 为 nil 无可清零
	priv.Precompute()
	require.NotNil(t, priv.Precomputed.Dp)
	require.NotNil(t, priv.Precomputed.Dq)
	require.NotNil(t, priv.Precomputed.Qinv)

	kp.Reset()

	assert.Empty(t, priv.Precomputed.Dp.Bytes(), "Reset 后 RSA Dp 应被清零")
	assert.Empty(t, priv.Precomputed.Dq.Bytes(), "Reset 后 RSA Dq 应被清零")
	assert.Empty(t, priv.Precomputed.Qinv.Bytes(), "Reset 后 RSA Qinv 应被清零")
	for i, crt := range priv.Precomputed.CRTValues {
		assert.Empty(t, crt.Exp.Bytes(), "Reset 后 CRTValues[%d].Exp 应被清零", i)
		assert.Empty(t, crt.Coeff.Bytes(), "Reset 后 CRTValues[%d].Coeff 应被清零", i)
		assert.Empty(t, crt.R.Bytes(), "Reset 后 CRTValues[%d].R 应被清零", i)
	}
}
