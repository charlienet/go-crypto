package agreement_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/charlienet/go-crypto/crypto"
	"github.com/charlienet/go-crypto/crypto/agreement"
)

// TestAgreementNew_Predefined 子包直接工厂 New：三预定义算法构造成功，
// Name() 与历史行为一致。
func TestAgreementNew_Predefined(t *testing.T) {
	cases := []struct {
		alg  crypto.AsymmetricAlgorithm
		name string
	}{
		{crypto.ECDH, "ECDH"},
		{crypto.X25519, "X25519"},
		{crypto.SM2, "SM2"},
	}

	for _, tc := range cases {
		t.Run(tc.alg.String(), func(t *testing.T) {
			ka, err := agreement.New(tc.alg)
			require.NoError(t, err)
			require.NotNil(t, ka)
			assert.Equal(t, tc.name, ka.Name())
		})
	}
}

// TestAgreementNew_SubsetRejected 子集外（RSA/ECDSA/ED25519）与非预定义值
// 拒绝：错误文本与根包 NewKeyAgreement 同型
// （"unsupported key agreement algorithm"）。
func TestAgreementNew_SubsetRejected(t *testing.T) {
	for _, alg := range []crypto.AsymmetricAlgorithm{crypto.RSA, crypto.ECDSA, crypto.ED25519, crypto.AsymmetricAlgorithm("INVALID")} {
		_, err := agreement.New(alg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported key agreement algorithm")
	}
}

// TestAgreementNew_RootConsistency 与根包 NewKeyAgreement 一致性：直接工厂
// 与注册表分发路径构造均成功，Name 一致（两条轨道落到同一实现）。
func TestAgreementNew_RootConsistency(t *testing.T) {
	for _, alg := range []crypto.AsymmetricAlgorithm{crypto.ECDH, crypto.X25519, crypto.SM2} {
		direct, err := agreement.New(alg)
		require.NoError(t, err)
		root, err := crypto.NewKeyAgreement(alg)
		require.NoError(t, err)
		assert.Equal(t, root.Name(), direct.Name(), "直接工厂与根包分发 Name 应一致")
	}
}
