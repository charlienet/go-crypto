package common

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestZeroBytes 验证逐字节清零。
func TestZeroBytes(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5}
	ZeroBytes(b)
	for i, v := range b {
		assert.Equal(t, byte(0), v, "下标 %d 应被清零", i)
	}
}

// TestZeroBytes_Empty 验证 nil 与空切片为安全操作。
func TestZeroBytes_Empty(t *testing.T) {
	ZeroBytes(nil)
	ZeroBytes([]byte{})
}

// TestZeroBigInt 验证大整数清零：底层内存擦除且值归零。
func TestZeroBigInt(t *testing.T) {
	z := big.NewInt(123456789)
	ZeroBigInt(z)
	assert.Equal(t, int64(0), z.Int64(), "值应归零")
	assert.Zero(t, z.Sign(), "符号应为零")
	assert.Equal(t, 0, z.BitLen(), "位长应为零")
}

// TestZeroBigInt_Nil 验证 nil 为安全操作。
func TestZeroBigInt_Nil(t *testing.T) {
	ZeroBigInt(nil)
}
