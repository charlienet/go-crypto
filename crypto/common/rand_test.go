package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFillRandom 验证 FillRandom 完整填充字节切片。
func TestFillRandom(t *testing.T) {
	b := make([]byte, 32)
	require.NoError(t, FillRandom(b))

	// 32 字节随机填充后不应全零
	assert.NotEqual(t, make([]byte, 32), b, "FillRandom 填充结果不应全零")

	// 两次填充结果不应相同（相同概率 2^-256，可忽略）
	b2 := make([]byte, 32)
	require.NoError(t, FillRandom(b2))
	assert.NotEqual(t, b, b2, "两次随机填充结果不应相同")
}

// TestFillRandom_Empty 验证空切片与 nil 均成功且无副作用。
func TestFillRandom_Empty(t *testing.T) {
	require.NoError(t, FillRandom(nil))
	require.NoError(t, FillRandom([]byte{}))
}
