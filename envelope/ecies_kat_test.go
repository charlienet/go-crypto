package envelope

// ECIES 自锚定 KAT（P1-1）：仿 gcx1 KAT 范式（envelope_test.go 的
// TestGCX1_KAT_* 风格），以固定收件人私钥 + 固定明文/固定 AAD 的一次性
// ECIESSeal 输出冻结为 hex 字面量，Open 方向逐字节断言。
// ECIESSeal 每次使用随机 ephemeral 密钥对与随机 nonce，Seal 方向不可复现，
// 故锚定 Open 方向：任何格式漂移（头部布局、ephPubLen 字段、nonce 位置、
// HKDF info、AAD 语义、tag 长度）都会使本测试必然失败。
//
// 生成方法（一次性，非运行时生成）：固定 D（测试专用密钥，勿用于生产），
// 明文/AAD 见常量，跑一次 ECIESSeal 后将输出 hex 固化为 eciesKATSealedHex。

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// eciesKATDHex 固定测试私钥标量（P-256，仅测试用途）。
	eciesKATDHex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	// 派生公钥未压缩点坐标（锚定密钥身份，防"私钥-公钥配对随实现漂移"）。
	eciesKATPubXHex = "515c3d6eb9e396b904d3feca7f54fdcd0cc1e997bf375dca515ad0a6c3b4035f"
	eciesKATPubYHex = "4536be3a50f318fbf9a5475902a221502bef0d57e08c53b2cc0a56f17d9f9354"

	eciesKATPlain = "ECIES self-anchored KAT payload"
	eciesKATAAD   = "go-crypto-ecies-kat-aad"

	// 冻结信封：41 || ephPub(65B) || nonce(12B) || ct(31B) || tag(16B)，共 125B。
	eciesKATSealedHex = "41" +
		"04edc8699c4c210621130ac6dd7ce890efc321af8f3d3d7f676da6e5ea46c8e6" +
		"17551c49587f7b1d0398a852577433f6038914f9596ec0919ad4212eb05e6120" +
		"84675794b98f9f6f8743f1425b6254bdf794614c5ac7c01bc509a95489d6ac32" +
		"58c4b2ae49af2a74390540d8e0ef21ec0b996090a778f9987c40f96f"
)

// eciesKATKey 从冻结常量重建固定测试私钥。
func eciesKATKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	d := new(big.Int)
	d, ok := d.SetString(eciesKATDHex, 16)
	require.True(t, ok)
	x := new(big.Int)
	x, ok = x.SetString(eciesKATPubXHex, 16)
	require.True(t, ok)
	y := new(big.Int)
	y, ok = y.SetString(eciesKATPubYHex, 16)
	require.True(t, ok)
	priv := &ecdsa.PrivateKey{D: d}
	priv.PublicKey.Curve = elliptic.P256()
	priv.PublicKey.X = x
	priv.PublicKey.Y = y
	return priv
}

// TestECIES_KAT_Open 冻结信封经 ECIESOpen 解出逐字节一致的明文。
func TestECIES_KAT_Open(t *testing.T) {
	priv := eciesKATKey(t)
	sealed, err := hex.DecodeString(eciesKATSealedHex)
	require.NoError(t, err, "KAT hex 常量必须可解码")

	// 布局锚定：ephPubLen 字段、总长 = 94 + len(plaintext)
	require.Equal(t, byte(eciesEphPubLen), sealed[0])
	require.Equal(t, eciesMinSealedLen+len(eciesKATPlain), len(sealed))

	pt, err := ECIESOpen(priv, sealed, []byte(eciesKATAAD))
	require.NoError(t, err, "KAT 信封必须能被当前实现解密")
	assert.Equal(t, []byte(eciesKATPlain), pt)
}

// TestECIES_KAT_TamperAnyByte 篡改冻结信封任一字节，解密必须失败：
// 头部/公钥区被点解析或 ECDH 拒绝，nonce/密文/tag 区被 GCM 认证拒绝。
func TestECIES_KAT_TamperAnyByte(t *testing.T) {
	priv := eciesKATKey(t)
	sealed, err := hex.DecodeString(eciesKATSealedHex)
	require.NoError(t, err)

	for i := range sealed {
		orig := sealed[i]
		sealed[i] = orig ^ 0xFF
		_, err := ECIESOpen(priv, sealed, []byte(eciesKATAAD))
		assert.Error(t, err, "篡改字节 %d 应解密失败", i)
		sealed[i] = orig
	}
}

// TestECIES_KAT_WrongAAD 冻结信封绑定固定 AAD，AAD 不匹配必须认证失败。
func TestECIES_KAT_WrongAAD(t *testing.T) {
	priv := eciesKATKey(t)
	sealed, err := hex.DecodeString(eciesKATSealedHex)
	require.NoError(t, err)

	_, err = ECIESOpen(priv, sealed, []byte("tampered-aad"))
	require.ErrorIs(t, err, ErrECIESAuthFailed)

	_, err = ECIESOpen(priv, sealed, nil)
	require.ErrorIs(t, err, ErrECIESAuthFailed)
}
