package agreement_test

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/charlienet/go-crypto"
	"github.com/charlienet/go-crypto/keymgr"
)

// TestECDH_PKCS8RoundTrip #18 完整闭环：ECDH GenerateKey（*ecdh.PrivateKey）
// → 导出 PKCS#8 → 解析回读（NIST 曲线为 *ecdsa.PrivateKey，标准库行为）
// → WithPrivateKey 注回 → 与对端派生的共享秘密一致（对端公钥亦经
// SPKI 往返回读为 *ecdsa.PublicKey，走 peer 双类型转换）。
func TestECDH_PKCS8RoundTrip(t *testing.T) {
	alice, err := crypto.NewKeyAgreement(crypto.ECDH)
	require.NoError(t, err)
	aliceKP, err := alice.GenerateKey()
	require.NoError(t, err)

	bob, err := crypto.NewKeyAgreement(crypto.ECDH)
	require.NoError(t, err)
	bobKP, err := bob.GenerateKey()
	require.NoError(t, err)

	// 私钥 PKCS#8 导出（Raw DER）→ 解析回读
	der, err := keymgr.MarshalPrivateKey(aliceKP.PrivateKey, keymgr.KeyFormatRaw)
	require.NoError(t, err)
	parsed, err := keymgr.ParsePrivateKeyPair(der, keymgr.KeyFormatRaw)
	require.NoError(t, err)
	// 标准库将 NIST 曲线 PKCS#8 回读为 *ecdsa.PrivateKey（非 *ecdh.PrivateKey），
	// 这正是 WithPrivateKey 接受双类型的原因
	_, isECDSAPriv := parsed.PrivateKey.(*ecdsa.PrivateKey)
	require.True(t, isECDSAPriv, "NIST 曲线 PKCS#8 应回读为 *ecdsa.PrivateKey")

	// 对端公钥 SPKI 导出 → 解析回读（*ecdsa.PublicKey）
	pubDER, err := keymgr.MarshalPublicKey(bobKP.PublicKey, keymgr.KeyFormatRaw)
	require.NoError(t, err)
	pubParsed, err := keymgr.ParsePublicKeyPair(pubDER, keymgr.KeyFormatRaw)
	require.NoError(t, err)
	_, isECDSAPub := pubParsed.PublicKey.(*ecdsa.PublicKey)
	require.True(t, isECDSAPub, "NIST 曲线 SPKI 应回读为 *ecdsa.PublicKey")

	// 注入回协商器（*ecdsa.PrivateKey 分支）
	alice2, err := crypto.NewKeyAgreement(crypto.ECDH)
	require.NoError(t, err)
	require.NoError(t, alice2.WithPrivateKey(parsed.PrivateKey))

	// 双向派生一致：Alice 用原始 ecdh 公钥，Bob 用原始 ecdh 公钥
	secretA, err := alice2.DeriveSharedSecret(bobKP.PublicKey)
	require.NoError(t, err)
	secretB, err := bob.DeriveSharedSecret(aliceKP.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, secretB, secretA, "PKCS#8 往返注回后共享秘密必须一致")

	// peer 双类型：Alice 用回读的 *ecdsa.PublicKey 派生，结果仍一致
	secretA2, err := alice2.DeriveSharedSecret(pubParsed.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, secretA, secretA2, "peer 经 SPKI 往返（*ecdsa.PublicKey）派生结果一致")
}

// TestECDH_WithPrivateKey_ECDHType *ecdh.PrivateKey 直接注入路径（与
// GenerateKey 内部类型一致），以及 X25519 私钥被 P-256 协商器拒绝。
func TestECDH_WithPrivateKey_ECDHType(t *testing.T) {
	ka, err := crypto.NewKeyAgreement(crypto.ECDH)
	require.NoError(t, err)

	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	require.NoError(t, ka.WithPrivateKey(priv))

	// 注入后正常协商
	peer, err := crypto.NewKeyAgreement(crypto.ECDH)
	require.NoError(t, err)
	peerKP, err := peer.GenerateKey()
	require.NoError(t, err)
	_, err = ka.DeriveSharedSecret(peerKP.PublicKey)
	require.NoError(t, err)

	// X25519 曲线私钥注入 P-256 协商器：拒绝（曲线校验）
	xPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	err = ka.WithPrivateKey(xPriv)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "curve")

	// 类型错误提示列出两种受支持类型
	err = ka.WithPrivateKey(struct{}{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "*ecdh.PrivateKey")
	assert.Contains(t, err.Error(), "*ecdsa.PrivateKey")
}

// TestX25519_PKCS8RoundTrip #18 对称性：X25519 同样可 PKCS#8 往返
//（X25519 曲线回读为 *ecdh.PrivateKey，与 NIST 曲线回读类型不同），
// 注回后与对端派生一致。
func TestX25519_PKCS8RoundTrip(t *testing.T) {
	alice, err := crypto.NewKeyAgreement(crypto.X25519)
	require.NoError(t, err)
	aliceKP, err := alice.GenerateKey()
	require.NoError(t, err)

	bob, err := crypto.NewKeyAgreement(crypto.X25519)
	require.NoError(t, err)
	bobKP, err := bob.GenerateKey()
	require.NoError(t, err)

	der, err := keymgr.MarshalPrivateKey(aliceKP.PrivateKey, keymgr.KeyFormatRaw)
	require.NoError(t, err)
	parsed, err := keymgr.ParsePrivateKeyPair(der, keymgr.KeyFormatRaw)
	require.NoError(t, err)
	// X25519 PKCS#8 回读为 *ecdh.PrivateKey（曲线 X25519）
	priv, isECDHPriv := parsed.PrivateKey.(*ecdh.PrivateKey)
	require.True(t, isECDHPriv, "X25519 PKCS#8 应回读为 *ecdh.PrivateKey")
	assert.Equal(t, ecdh.X25519(), priv.Curve())

	alice2, err := crypto.NewKeyAgreement(crypto.X25519)
	require.NoError(t, err)
	require.NoError(t, alice2.WithPrivateKey(parsed.PrivateKey))

	secretA, err := alice2.DeriveSharedSecret(bobKP.PublicKey)
	require.NoError(t, err)
	secretB, err := bob.DeriveSharedSecret(aliceKP.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, secretB, secretA, "X25519 PKCS#8 往返注回后共享秘密必须一致")
}

// TestECDH_DeriveSharedSecret_PeerTypeErrors peer 类型错误路径：
// 不支持的类型与跨曲线 peer 均被拒绝。
func TestECDH_DeriveSharedSecret_PeerTypeErrors(t *testing.T) {
	ka, err := crypto.NewKeyAgreement(crypto.ECDH)
	require.NoError(t, err)
	kp, err := ka.GenerateKey()
	require.NoError(t, err)
	_ = kp

	// 非 ECDH 类型（如 rsa 公钥占位）：拒绝
	_, err = ka.DeriveSharedSecret(struct{}{})
	assert.Error(t, err)

	// X25519 公钥作 peer：*ecdsa 断言失败路径 → 错误
	xAlgo, err := crypto.NewKeyAgreement(crypto.X25519)
	require.NoError(t, err)
	xKP, err := xAlgo.GenerateKey()
	require.NoError(t, err)
	_, err = ka.DeriveSharedSecret(xKP.PublicKey)
	assert.Error(t, err, "X25519 公钥不能作 ECDH peer")
}