package asym_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/charlienet/go-crypto"
	"github.com/charlienet/go-crypto/asym"
)

// TestAsymNew_Predefined 子包直接工厂 New：四预定义算法构造成功，
// Name() 与历史行为一致（Ed25519 保留驼峰输出 "Ed25519"）。
func TestAsymNew_Predefined(t *testing.T) {
	cases := []struct {
		alg  crypto.AsymmetricAlgorithm
		name string
	}{
		{crypto.RSA, "RSA"},
		{crypto.ECDSA, "ECDSA"},
		{crypto.ED25519, "Ed25519"},
		{crypto.SM2, "SM2"},
	}

	for _, tc := range cases {
		t.Run(tc.alg.String(), func(t *testing.T) {
			a, err := asym.New(tc.alg)
			require.NoError(t, err)
			require.NotNil(t, a)
			assert.Equal(t, tc.name, a.Name())
		})
	}
}

// TestAsymNew_SubsetRejected 子集外（ECDH/X25519）与非预定义值拒绝：
// 错误文本与根包 NewAsymmetric 同型（"unsupported asymmetric algorithm"）。
func TestAsymNew_SubsetRejected(t *testing.T) {
	for _, alg := range []crypto.AsymmetricAlgorithm{crypto.ECDH, crypto.X25519, crypto.AsymmetricAlgorithm("INVALID")} {
		_, err := asym.New(alg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported asymmetric algorithm")
	}
}

// TestAsymNew_RootConsistency 与根包 NewAsymmetric 一致性：直接工厂与
// 注册表分发路径构造均成功，Name 一致（两条轨道落到同一实现）。
func TestAsymNew_RootConsistency(t *testing.T) {
	for _, alg := range []crypto.AsymmetricAlgorithm{crypto.RSA, crypto.ECDSA, crypto.ED25519, crypto.SM2} {
		direct, err := asym.New(alg)
		require.NoError(t, err)
		root, err := crypto.NewAsymmetric(alg)
		require.NoError(t, err)
		assert.Equal(t, root.Name(), direct.Name(), "直接工厂与根包分发 Name 应一致")
	}
}
