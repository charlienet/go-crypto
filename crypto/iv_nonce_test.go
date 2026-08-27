package crypto

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWithHexIV_RoundTrip(t *testing.T) {
	key := make([]byte, 16)
	iv := make([]byte, 16)
	// 填充确定值
	for i := range iv {
		iv[i] = byte(i)
	}
	hexIV := hex.EncodeToString(iv)

	pt := []byte("test data here!")
	ct, err := Encrypt(AES128, CBC, pt,
		WithKey(key), WithHexIV(hexIV))
	require.NoError(t, err)

	got, err := Decrypt(AES128, CBC, ct,
		WithKey(key), WithHexIV(hexIV))
	require.NoError(t, err)
	assert.Equal(t, pt, got)
}

func TestWithBase64IV_RoundTrip(t *testing.T) {
	key := make([]byte, 16)
	iv := make([]byte, 16)
	// 填充确定值
	for i := range iv {
		iv[i] = byte(i)
	}
	base64IV := base64.StdEncoding.EncodeToString(iv)

	pt := []byte("test data here!")
	ct, err := Encrypt(AES128, CBC, pt,
		WithKey(key), WithBase64IV(base64IV))
	require.NoError(t, err)

	got, err := Decrypt(AES128, CBC, ct,
		WithKey(key), WithBase64IV(base64IV))
	require.NoError(t, err)
	assert.Equal(t, pt, got)
}

func TestWithHexNonce_RoundTrip(t *testing.T) {
	key := make([]byte, 16)
	nonce := make([]byte, 12) // GCM nonce 固定 12 字节
	// 填充确定值
	for i := range nonce {
		nonce[i] = byte(i)
	}
	hexNonce := hex.EncodeToString(nonce)

	pt := []byte("test data here!")
	ct, err := Encrypt(AES128, GCM, pt,
		WithKey(key), WithHexNonce(hexNonce))
	require.NoError(t, err)

	got, err := Decrypt(AES128, GCM, ct,
		WithKey(key), WithHexNonce(hexNonce))
	require.NoError(t, err)
	assert.Equal(t, pt, got)
}

func TestWithBase64Nonce_RoundTrip(t *testing.T) {
	key := make([]byte, 16)
	nonce := make([]byte, 12) // GCM nonce 固定 12 字节
	// 填充确定值
	for i := range nonce {
		nonce[i] = byte(i)
	}
	base64Nonce := base64.StdEncoding.EncodeToString(nonce)

	pt := []byte("test data here!")
	ct, err := Encrypt(AES128, GCM, pt,
		WithKey(key), WithBase64Nonce(base64Nonce))
	require.NoError(t, err)

	got, err := Decrypt(AES128, GCM, ct,
		WithKey(key), WithBase64Nonce(base64Nonce))
	require.NoError(t, err)
	assert.Equal(t, pt, got)
}

func TestWithHexIV_Invalid(t *testing.T) {
	_, err := Encrypt(AES128, CBC, []byte("test"),
		WithKey(make([]byte, 16)), WithHexIV("zz-not-hex"))
	assert.ErrorIs(t, err, ErrInvalidHexIV)
}

func TestWithBase64IV_Invalid(t *testing.T) {
	_, err := Encrypt(AES128, CBC, []byte("test"),
		WithKey(make([]byte, 16)), WithBase64IV("!!!not-base64!!!"))
	assert.ErrorIs(t, err, ErrInvalidBase64IV)
}

func TestWithHexNonce_Invalid(t *testing.T) {
	_, err := Encrypt(AES128, GCM, []byte("test"),
		WithKey(make([]byte, 16)), WithHexNonce("zz"))
	assert.ErrorIs(t, err, ErrInvalidHexNonce)
}

func TestWithBase64Nonce_Invalid(t *testing.T) {
	_, err := Encrypt(AES128, GCM, []byte("test"),
		WithKey(make([]byte, 16)), WithBase64Nonce("!!!"))
	assert.ErrorIs(t, err, ErrInvalidBase64Nonce)
}

func TestIV_Override(t *testing.T) {
	// WithHexIV 覆盖 WithIV，后者生效
	key := make([]byte, 16)
	iv1 := make([]byte, 16) // 全零
	iv2 := make([]byte, 16)
	for i := range iv2 {
		iv2[i] = byte(i)
	}
	hexIV2 := hex.EncodeToString(iv2)

	pt := []byte("override test!!") // 16B, 对齐

	// 用 WithIV(wrong) + WithHexIV(correct) → 应该用 hexIV2
	ct, err := Encrypt(AES128, CBC, pt,
		WithKey(key), WithIV(iv1), WithHexIV(hexIV2))
	require.NoError(t, err)

	got, err := Decrypt(AES128, CBC, ct,
		WithKey(key), WithHexIV(hexIV2))
	require.NoError(t, err)
	assert.Equal(t, pt, got)
}

func TestNonce_Override(t *testing.T) {
	// WithBase64Nonce 覆盖 WithNonce，后者生效
	key := make([]byte, 16)
	nonce1 := make([]byte, 12) // 全零
	nonce2 := make([]byte, 12)
	for i := range nonce2 {
		nonce2[i] = byte(i)
	}
	base64Nonce2 := base64.StdEncoding.EncodeToString(nonce2)

	pt := []byte("override test!!") // 16B, 对齐

	// 用 WithNonce(wrong) + WithBase64Nonce(correct) → 应该用 base64Nonce2
	ct, err := Encrypt(AES128, GCM, pt,
		WithKey(key), WithNonce(nonce1), WithBase64Nonce(base64Nonce2))
	require.NoError(t, err)

	got, err := Decrypt(AES128, GCM, ct,
		WithKey(key), WithBase64Nonce(base64Nonce2))
	require.NoError(t, err)
	assert.Equal(t, pt, got)
}

func TestIV_ClearErrorOnByteOverride(t *testing.T) {
	// 当 WithIV 覆盖 WithHexIV 时，应该清除 IVError
	key := make([]byte, 16)
	iv := make([]byte, 16)
	for i := range iv {
		iv[i] = byte(i)
	}

	pt := []byte("test clear error")
	
	// 使用无效 hex IV，然后用有效的字节 IV 覆盖，应该成功
	ct, err := Encrypt(AES128, CBC, pt,
		WithKey(key), WithHexIV("invalid-hex"), WithIV(iv))
	require.NoError(t, err)

	got, err := Decrypt(AES128, CBC, ct,
		WithKey(key), WithIV(iv))
	require.NoError(t, err)
	assert.Equal(t, pt, got)
}

func TestNonce_ClearErrorOnByteOverride(t *testing.T) {
	// 当 WithNonce 覆盖 WithBase64Nonce 时，应该清除 NonceError
	key := make([]byte, 16)
	nonce := make([]byte, 12)
	for i := range nonce {
		nonce[i] = byte(i)
	}

	pt := []byte("test clear error")
	
	// 使用无效 base64 nonce，然后用有效的字节 nonce 覆盖，应该成功
	ct, err := Encrypt(AES128, GCM, pt,
		WithKey(key), WithBase64Nonce("invalid-base64"), WithNonce(nonce))
	require.NoError(t, err)

	got, err := Decrypt(AES128, GCM, ct,
		WithKey(key), WithNonce(nonce))
	require.NoError(t, err)
	assert.Equal(t, pt, got)
}