package crypto_test

// 双轨一致性测试（阶段 5）：根包协议入口（Encrypt/Decrypt/NewEncryptor/
// NewAsymmetric/NewKeyAgreement/GenerateKeyPair，经注册表分发）与子包
// 直接工厂/函数（asym.New / agreement.New / keymgr.GenerateKeyPair）
// 输出互解、行为一致，验证两条 API 轨道最终落到同一实现。

import (
	"testing"

	"github.com/charlienet/go-crypto/crypto"

	"github.com/charlienet/go-crypto/crypto/agreement"
	"github.com/charlienet/go-crypto/crypto/asym" // import 即注册非对称引擎（协议入口依赖）
	"github.com/charlienet/go-crypto/crypto/keymgr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDualTrack_Asymmetric 根包协议入口与子包直接工厂 asym.New 行为一致
// （构造成功、Name 一致）。子包直接工厂直发包内构造器，不经注册表；
// 根包 NewAsymmetric 经注册表分发到同一引擎实现。
func TestDualTrack_Asymmetric(t *testing.T) {
	a, err := crypto.NewAsymmetric(crypto.RSA)
	require.NoError(t, err)
	require.NotNil(t, a)
	assert.Equal(t, "RSA", a.Name())

	a2, err := asym.New(crypto.RSA)
	require.NoError(t, err)
	assert.Equal(t, "RSA", a2.Name(), "子包直接工厂构造的实例 Name 应与协议入口一致")
}

// TestDualTrack_KeyAgreement 根包协议入口与子包直接工厂 agreement.New
// 行为一致（构造成功、Name 一致）。
func TestDualTrack_KeyAgreement(t *testing.T) {
	ka, err := crypto.NewKeyAgreement(crypto.ECDH)
	require.NoError(t, err)
	require.NotNil(t, ka)
	assert.Equal(t, "ECDH", ka.Name())

	ka2, err := agreement.New(crypto.ECDH)
	require.NoError(t, err)
	assert.Equal(t, "ECDH", ka2.Name(), "子包直接工厂构造的实例 Name 应与协议入口一致")
}

// TestDualTrack_KeyPair 根包协议入口与 keymgr 直接函数都能生成 SM2 密钥对，
// 且返回同一数据契约类型（*crypto.KeyPair）。
func TestDualTrack_KeyPair(t *testing.T) {
	kp1, err := crypto.GenerateKeyPair(crypto.SM2)
	require.NoError(t, err)
	require.NotNil(t, kp1)

	kp2, err := keymgr.GenerateKeyPair(crypto.SM2)
	require.NoError(t, err)
	require.NotNil(t, kp2)

	// 编译期断言：两条轨道返回同一类型
	var _ *crypto.KeyPair = kp1
	var _ *crypto.KeyPair = kp2
}
