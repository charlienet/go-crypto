package kdf

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestArgon2id_KAT 断言公开 API Argon2id 在 RFC 9106 §5.1 样例参数下产出的锚定密钥。
//
// 参数取自 RFC 9106 §5.1（password=0x01×32、salt=0x02×16、t=3、m=32 KiB、p=4、tagLen=32），
// 但 m=32 恰满足本包 memory ≥ 8*threads(=32) 下界。
//
// 重要说明（勿误判为失败）：RFC 9106 §5.3 的官方 tag
//
//	0d640df58d78766c08c037a34a8b53c9d001ef0452d75b65eb52520e96b01e65
//
// 是在 Secret=0x03×8、AssociatedData=0x04×12 非空的前提下计算的。
// 本库公开 API kdf.Argon2id 映射到 x/crypto 的 argon2.IDKey，后者不接受 secret/ad，
// 等价于 Secret/ad 均为空——因此无法逐字节复现 RFC §5.3 官方向量。
// 下面锚定值为 x/crypto v0.54.0 空 secret/ad 的本实现实算结果，作为回归冻结基准，
// 而非 RFC §5.3 的官方复现。
func TestArgon2id_KAT(t *testing.T) {
	password := bytesRepeat(0x01, 32)
	salt := bytesRepeat(0x02, 16)

	key, err := Argon2id(password, salt, 3, 32, 4, 32)
	require.NoError(t, err)
	require.Len(t, key, 32)

	want, err := hex.DecodeString("03aab965c12001c9d7d0d2de33192c0494b684bb148196d73c1df1acaf6d0c2e")
	require.NoError(t, err)
	assert.Equal(t, want, key)
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
