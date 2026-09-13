package kdf

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHKDF_RFC5869 覆盖 RFC 5869 附录 A 的 SHA-256 官方向量。
// Case 1 已在 kdf_test.go:TestHKDF_SHA256 断言，此处补 Case 2 / Case 3。
// 注：RFC 5869 未提供 SHA-384/SHA-512 官方 KAT，勿伪造。
func TestHKDF_RFC5869(t *testing.T) {
	cases := []struct {
		name   string
		hash   string
		ikm    string
		salt   []byte // nil 表示零长 salt（Go 侧传 nil，x/crypto 内部按 HashLen 个零字节处理）
		info   []byte
		keyLen int
		okm    string
	}{
		{
			// RFC 5869 §A.2：Hash=SHA-256，IKM/salt/info 各 80 字节递增序列，L=82
			name:   "Case2",
			hash:   "SHA-256",
			ikm:    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
			salt:   mustHex(t, "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf"),
			info:   mustHex(t, "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
			keyLen: 82,
			okm:    "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
		},
		{
			// RFC 5869 §A.3：无 salt / 无 info（零长），L=42。Go 侧传 nil。
			name:   "Case3",
			hash:   "SHA-256",
			ikm:    "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			salt:   nil,
			info:   nil,
			keyLen: 42,
			okm:    "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ikm := mustHex(t, tc.ikm)
			key, err := HKDF(tc.hash, ikm, tc.salt, tc.info, tc.keyLen)
			require.NoError(t, err)
			assert.Len(t, key, tc.keyLen)

			want, err := hex.DecodeString(tc.okm)
			require.NoError(t, err)
			assert.Equal(t, want, key)
		})
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}
