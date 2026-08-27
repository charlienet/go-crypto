package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// ==================== NormalizeAlgorithm（自 envelope_test.go 迁入） ====================

func TestNormalizeAlgorithm_ExactMatch(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"SM4", AlgorithmSM4},
		{"AES-128", AlgorithmAES128},
		{"AES-192", AlgorithmAES192},
		{"AES-256", AlgorithmAES256},
		{"DES", AlgorithmDES},
		{"3DES", Algorithm3DES},
		{"SM2", AlgorithmSM2},
		{"RSA", AlgorithmRSA},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := NormalizeAlgorithm(tt.input)
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNormalizeAlgorithm_CaseInsensitive(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"sm4", AlgorithmSM4},
		{"Sm4", AlgorithmSM4},
		{"aes-128", AlgorithmAES128},
		{"aes-192", AlgorithmAES192},
		{"aes-256", AlgorithmAES256},
		{"des", AlgorithmDES},
		{"3des", Algorithm3DES},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := NormalizeAlgorithm(tt.input)
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNormalizeAlgorithm_Alias(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"AES", AlgorithmAES128}, // "AES" 默认归一为 AES-128
		{"aes", AlgorithmAES128},
		{"AES128", AlgorithmAES128}, // 去除连字符匹配
		{"aes128", AlgorithmAES128},
		{"AES192", AlgorithmAES192},
		{"aes192", AlgorithmAES192},
		{"AES256", AlgorithmAES256},
		{"aes256", AlgorithmAES256},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := NormalizeAlgorithm(tt.input)
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNormalizeAlgorithm_Unknown(t *testing.T) {
	_, err := NormalizeAlgorithm("BLOWFISH")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported algorithm")
}
