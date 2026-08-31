package crypto_test

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"math/big"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rootcrypto "github.com/charlienet/go-crypto"
	"github.com/charlienet/go-crypto/asym"
	_ "github.com/charlienet/go-crypto/keymgr" // 注册密钥对生成器（GenerateKeyPair 依赖）
)

// ==================== AsSigner：四型签名密钥均获 Signer ====================

func TestKeyPair_AsSigner_AllSignableTypes(t *testing.T) {
	cases := []struct {
		name string
		algo rootcrypto.AsymmetricAlgorithm
	}{
		{"RSA", rootcrypto.RSA},
		{"ECDSA", rootcrypto.ECDSA},
		{"ED25519", rootcrypto.ED25519},
		{"SM2", rootcrypto.SM2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kp, err := rootcrypto.GenerateKeyPair(tc.algo)
			require.NoError(t, err)

			signer, err := kp.AsSigner()
			require.NoError(t, err, "私钥应实现 crypto.Signer")
			require.NotNil(t, signer)

			// Public() 类型必须与 KeyPair.PublicKey 一致
			assert.Equal(t, reflect.TypeOf(kp.PublicKey), reflect.TypeOf(signer.Public()),
				"algorithm=%s Public() 类型应与 KeyPair.PublicKey 一致", tc.name)
			// 公钥值一致（同一密钥的视图）
			assert.Equal(t, kp.PublicKey, signer.Public())
		})
	}
}

// ==================== 不可签名密钥：nil / X25519 ====================

func TestKeyPair_AsSigner_NotSigner(t *testing.T) {
	t.Run("nil private key", func(t *testing.T) {
		kp := &rootcrypto.KeyPair{}
		_, err := kp.AsSigner()
		assert.ErrorIs(t, err, rootcrypto.ErrKeyPairNotSigner)
	})

	t.Run("X25519 (key agreement only)", func(t *testing.T) {
		priv, err := ecdh.X25519().GenerateKey(rand.Reader)
		require.NoError(t, err)
		kp := &rootcrypto.KeyPair{PrivateKey: priv, PublicKey: priv.PublicKey()}
		_, err = kp.AsSigner()
		assert.ErrorIs(t, err, rootcrypto.ErrKeyPairNotSigner)
		assert.Contains(t, err.Error(), "key agreement")
	})
}

// ==================== ECDSA：Signer.Sign 产物经 asym 包 Verify 可验证 ====================

// dsSignature ASN.1 DER ECDSA 签名结构（与 asym/ecdsa.go 解析一致）。
type dsSignature struct {
	R, S *big.Int
}

// ecdsaSigLowS 判断 DER 编码的 ECDSA 签名是否低 S（s ≤ N/2）。
// asym 包 Verify 为防可塑性（签名翻转）拒绝高 S 签名；而标准库
// crypto.Signer.Sign（ECDSA）不保证低 S（约 1/2 概率产出高 S）。测试
// 以重签直到低 S 的方式验证"Signer 产物可被库内 Verify 验证"的互操作性，
// 32 次重签内全部失败的几率约 2^-32，可忽略。
func ecdsaSigLowS(t *testing.T, pub *ecdsa.PublicKey, sig []byte) bool {
	t.Helper()
	var parsed dsSignature
	if _, err := asn1.Unmarshal(sig, &parsed); err != nil || parsed.R == nil || parsed.S == nil {
		return false
	}
	halfOrder := new(big.Int).Rsh(new(big.Int).Set(pub.Curve.Params().N), 1)
	return parsed.S.Cmp(halfOrder) <= 0
}

func TestKeyPair_AsSigner_ECDSA_SignVerify(t *testing.T) {
	kp, err := rootcrypto.GenerateKeyPair(rootcrypto.ECDSA)
	require.NoError(t, err)

	signer, err := kp.AsSigner()
	require.NoError(t, err)

	// crypto.Signer.Sign 接收摘要（已哈希）+ 摘要算法（asym/ecdsa.go 的
	// Verify 对 data 重新做同算法哈希，二者必须匹配）
	data := []byte("as-signer ecdsa verify")
	digest := sha256.Sum256(data)

	var sig []byte
	for range 32 {
		sig, err = signer.Sign(rand.Reader, digest[:], crypto.SHA256)
		require.NoError(t, err)
		if ecdsaSigLowS(t, kp.PublicKey.(*ecdsa.PublicKey), sig) {
			break
		}
		sig = nil
	}
	require.NotNil(t, sig, "32 次重签均未产出低 S 签名（概率约 2^-32）")

	// 经 asym 包 ECDSA Verify 校验（P-256 + SHA-256 默认配置）
	verifier, err := asym.New(rootcrypto.ECDSA, rootcrypto.WithPublicKeyObject(kp.PublicKey))
	require.NoError(t, err)
	assert.True(t, verifier.Verify(data, sig), "Signer.Sign 产物应被库内 ECDSA Verify 验证")
}
