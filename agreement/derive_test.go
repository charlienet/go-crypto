package agreement_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/charlienet/go-crypto"
	"github.com/charlienet/go-crypto/agreement"
	"github.com/charlienet/go-crypto/kdf"
)

// TestDeriveKey_ECDH #19：ECDH 双方一步式派生对称相等，且与手工
// DeriveSharedSecret + HKDF 结果一致（通用回退路径验证）。
func TestDeriveKey_ECDH(t *testing.T) {
	alice, err := crypto.NewKeyAgreement(crypto.ECDH)
	require.NoError(t, err)
	aliceKP, err := alice.GenerateKey()
	require.NoError(t, err)

	bob, err := crypto.NewKeyAgreement(crypto.ECDH)
	require.NoError(t, err)
	bobKP, err := bob.GenerateKey()
	require.NoError(t, err)

	salt := []byte("fixed-salt-16B")
	info := []byte("session/key@2026")

	kA, err := agreement.DeriveKey(alice, bobKP.PublicKey, salt, info, 32)
	require.NoError(t, err)
	kB, err := agreement.DeriveKey(bob, aliceKP.PublicKey, salt, info, 32)
	require.NoError(t, err)
	assert.Equal(t, kA, kB, "双方一步式派生必须一致")

	// info 域分离：不同 info 派生不同密钥
	kOther, err := agreement.DeriveKey(alice, bobKP.PublicKey, salt, []byte("other"), 32)
	require.NoError(t, err)
	assert.NotEqual(t, kA, kOther)

	// 与手工 DeriveSharedSecret + HKDF("SHA-256") 一致
	secret, err := alice.DeriveSharedSecret(bobKP.PublicKey)
	require.NoError(t, err)
	manual, err := kdf.HKDF("SHA-256", secret, salt, info, 32)
	require.NoError(t, err)
	assert.Equal(t, manual, kA, "回退路径必须与手工 DeriveSharedSecret+HKDF 一致")

	// keyLen 非法
	_, err = agreement.DeriveKey(alice, bobKP.PublicKey, salt, info, 0)
	assert.Error(t, err)
	_, err = agreement.DeriveKey(alice, bobKP.PublicKey, salt, info, -1)
	assert.Error(t, err)
}

// TestDeriveKey_X25519：X25519 双方一步式派生对称相等。
func TestDeriveKey_X25519(t *testing.T) {
	alice, err := crypto.NewKeyAgreement(crypto.X25519)
	require.NoError(t, err)
	aliceKP, err := alice.GenerateKey()
	require.NoError(t, err)

	bob, err := crypto.NewKeyAgreement(crypto.X25519)
	require.NoError(t, err)
	bobKP, err := bob.GenerateKey()
	require.NoError(t, err)

	kA, err := agreement.DeriveKey(alice, bobKP.PublicKey, []byte("salt"), nil, 16)
	require.NoError(t, err)
	kB, err := agreement.DeriveKey(bob, aliceKP.PublicKey, []byte("salt"), nil, 16)
	require.NoError(t, err)
	assert.Equal(t, kA, kB, "X25519 双方一步式派生必须一致")
}

// TestDeriveKey_SM2Disabled：SM2 协商 DeriveSharedSecret 已禁用，
// 一步式派生经通用回退自然返回既有哨兵错误。
func TestDeriveKey_SM2Disabled(t *testing.T) {
	ka, err := crypto.NewKeyAgreement(crypto.SM2)
	require.NoError(t, err)
	kp, err := ka.GenerateKey()
	require.NoError(t, err)

	_, err = agreement.DeriveKey(ka, kp.PublicKey, nil, nil, 32)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "sm2 key agreement")
}