package agreement_test

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/emmansun/gmsm/sm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/charlienet/go-crypto/crypto"
)

func TestECDH_KeyAgreement(t *testing.T) {
	ka, err := crypto.NewKeyAgreement(crypto.ECDH)
	require.NoError(t, err)

	// Alice 生成密钥
	aliceKP, err := ka.GenerateKey()
	require.NoError(t, err)

	// Bob 生成密钥
	ka2, _ := crypto.NewKeyAgreement(crypto.ECDH)
	bobKP, err := ka2.GenerateKey()
	require.NoError(t, err)

	// Alice 计算共享密钥
	secret1, err := ka.DeriveSharedSecret(bobKP.PublicKey)
	require.NoError(t, err)

	// Bob 计算共享密钥
	secret2, err := ka2.DeriveSharedSecret(aliceKP.PublicKey)
	require.NoError(t, err)

	// 双方应该得到相同的共享密钥
	assert.Equal(t, secret1, secret2)
}

func TestX25519_KeyAgreement(t *testing.T) {
	ka, err := crypto.NewKeyAgreement(crypto.X25519)
	require.NoError(t, err)

	aliceKP, err := ka.GenerateKey()
	require.NoError(t, err)

	ka2, _ := crypto.NewKeyAgreement(crypto.X25519)
	bobKP, err := ka2.GenerateKey()
	require.NoError(t, err)

	secret1, err := ka.DeriveSharedSecret(bobKP.PublicKey)
	require.NoError(t, err)

	secret2, err := ka2.DeriveSharedSecret(aliceKP.PublicKey)
	require.NoError(t, err)

	assert.Equal(t, secret1, secret2)
}

func TestSM2_KeyAgreement(t *testing.T) {
	ka, err := crypto.NewKeyAgreement(crypto.SM2)
	require.NoError(t, err)

	// GenerateKey 保留：仍可用于 SM2 密钥生成
	aliceKP, err := ka.GenerateKey()
	require.NoError(t, err)
	assert.NotNil(t, aliceKP.PrivateKey)
	assert.NotNil(t, aliceKP.PublicKey)

	ka2, _ := crypto.NewKeyAgreement(crypto.SM2)
	bobKP, err := ka2.GenerateKey()
	require.NoError(t, err)
	assert.NotNil(t, bobKP.PublicKey)

	// DeriveSharedSecret 已禁用（裸标量乘法实现不安全）：
	// 必须返回明确错误，且不产出任何共享密钥
	secret1, err := ka.DeriveSharedSecret(bobKP.PublicKey)
	assert.Error(t, err)
	assert.Nil(t, secret1)
	assert.Contains(t, err.Error(), "sm2 key agreement")

	secret2, err := ka2.DeriveSharedSecret(aliceKP.PublicKey)
	assert.Error(t, err)
	assert.Nil(t, secret2)
	assert.Contains(t, err.Error(), "sm2 key agreement")
}

func TestKeyAgreement_Concurrent(t *testing.T) {
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func() {
			ka, _ := crypto.NewKeyAgreement(crypto.X25519)
			kp, err := ka.GenerateKey()
			assert.NoError(t, err)
			assert.NotNil(t, kp)
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

// TestKeyAgreement_Unsupported 子集外/非预定义拒绝：
// RSA/ECDSA/ED25519 是非对称加解密算法，协商入口必须拒绝；非预定义值未注册同样拒绝。
func TestKeyAgreement_Unsupported(t *testing.T) {
	_, err := crypto.NewKeyAgreement(crypto.RSA)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported key agreement algorithm")

	_, err = crypto.NewKeyAgreement(crypto.ECDSA)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported key agreement algorithm")

	_, err = crypto.NewKeyAgreement(crypto.ED25519)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported key agreement algorithm")

	// 非预定义字符串值：走注册表查询，未注册报 engine 缺失错误
	_, err = crypto.NewKeyAgreement(crypto.AsymmetricAlgorithm("INVALID"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no engine registered for")
	assert.Contains(t, err.Error(), "github.com/charlienet/go-crypto/crypto/agreement")
}

// --- 私钥注入测试（P2） ---

func TestECDH_KeyAgreement_WithPrivateKey(t *testing.T) {
	// 注入固定 ECDSA P-256 私钥（存量密钥/密钥轮换场景）
	fixed, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	alice, err := crypto.NewKeyAgreement(crypto.ECDH)
	require.NoError(t, err)
	require.NoError(t, alice.WithPrivateKey(fixed))

	bob, err := crypto.NewKeyAgreement(crypto.ECDH)
	require.NoError(t, err)
	bobKP, err := bob.GenerateKey()
	require.NoError(t, err)

	// 注入私钥后 Alice 可正常协商
	secretAlice, err := alice.DeriveSharedSecret(bobKP.PublicKey)
	require.NoError(t, err)

	// 由注入的 ecdsa 公钥构造 ecdh 公钥，Bob 侧反向计算，双方结果应一致
	alicePubDER := elliptic.Marshal(elliptic.P256(), fixed.X, fixed.Y)
	aliceECDPub, err := ecdh.P256().NewPublicKey(alicePubDER)
	require.NoError(t, err)
	secretBob, err := bob.DeriveSharedSecret(aliceECDPub)
	require.NoError(t, err)

	assert.Equal(t, secretAlice, secretBob)

	// 相同注入私钥结果确定（重复注入后一次为准）
	alice2, err := crypto.NewKeyAgreement(crypto.ECDH)
	require.NoError(t, err)
	require.NoError(t, alice2.WithPrivateKey(fixed))
	secretAlice2, err := alice2.DeriveSharedSecret(bobKP.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, secretAlice, secretAlice2)
}

func TestECDH_KeyAgreement_WithPrivateKey_TypeMismatch(t *testing.T) {
	ka, err := crypto.NewKeyAgreement(crypto.ECDH)
	require.NoError(t, err)

	// 非 *ecdsa.PrivateKey 类型：拒绝
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	err = ka.WithPrivateKey(rsaKey)
	assert.Error(t, err)

	// 曲线不匹配（P-384，协商器固定 P-256）：拒绝
	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	err = ka.WithPrivateKey(p384Key)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "curve")
}

func TestX25519_KeyAgreement_WithPrivateKey(t *testing.T) {
	// 构造固定 X25519 私钥（与 GenerateKey 内部类型一致：*ecdh.PrivateKey）
	seed := make([]byte, 32)
	_, err := rand.Read(seed)
	require.NoError(t, err)
	fixed, err := ecdh.X25519().NewPrivateKey(seed)
	require.NoError(t, err)

	alice, err := crypto.NewKeyAgreement(crypto.X25519)
	require.NoError(t, err)
	require.NoError(t, alice.WithPrivateKey(fixed))

	bob, err := crypto.NewKeyAgreement(crypto.X25519)
	require.NoError(t, err)
	bobKP, err := bob.GenerateKey()
	require.NoError(t, err)

	// 注入私钥后 Alice 可正常协商
	secretAlice, err := alice.DeriveSharedSecret(bobKP.PublicKey)
	require.NoError(t, err)

	// Bob 侧用注入私钥的公钥反向计算，双方结果应一致
	secretBob, err := bob.DeriveSharedSecret(fixed.PublicKey())
	require.NoError(t, err)
	assert.Equal(t, secretAlice, secretBob)

	// 相同注入私钥结果确定
	alice2, err := crypto.NewKeyAgreement(crypto.X25519)
	require.NoError(t, err)
	require.NoError(t, alice2.WithPrivateKey(fixed))
	secretAlice2, err := alice2.DeriveSharedSecret(bobKP.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, secretAlice, secretAlice2)
}

func TestX25519_KeyAgreement_WithPrivateKey_TypeMismatch(t *testing.T) {
	ka, err := crypto.NewKeyAgreement(crypto.X25519)
	require.NoError(t, err)

	// 非 *ecdh.PrivateKey 类型：拒绝
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	err = ka.WithPrivateKey(ecdsaKey)
	assert.Error(t, err)

	// NIST 曲线 ecdh 私钥（非 X25519）：拒绝
	nistPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	err = ka.WithPrivateKey(nistPriv)
	assert.Error(t, err)
}

func TestSM2_KeyAgreement_WithPrivateKey_Unsupported(t *testing.T) {
	ka, err := crypto.NewKeyAgreement(crypto.SM2)
	require.NoError(t, err)

	// SM2 密钥协商已禁用：注入入口必须返回明确错误
	sm2Key, err := sm2.GenerateKey(rand.Reader)
	require.NoError(t, err)
	err = ka.WithPrivateKey(sm2Key)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "sm2 key agreement")
}
