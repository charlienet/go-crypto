package crypto

import "fmt"

// 算法常量，用于高层 API 的 algorithm 参数。
const (
	AlgorithmSM4    = "SM4"
	AlgorithmAES128 = "AES-128"
	AlgorithmAES192 = "AES-192"
	AlgorithmAES256 = "AES-256"
	AlgorithmDES    = "DES"
	Algorithm3DES   = "3DES"
	AlgorithmSM2    = "SM2"
	AlgorithmRSA    = "RSA"
	AlgorithmECDH   = "ECDH"
	AlgorithmX25519 = "X25519"
	AlgorithmECDSA  = "ECDSA"
	AlgorithmED25519 = "ED25519"
)

// algorithmNameMap 算法名归一化查找表（大写键 → 标准算法常量）。
// 包级只读变量，避免 NormalizeAlgorithm 每次调用重建 map，且并发只读安全。
var algorithmNameMap = map[string]string{
	"SM4":     AlgorithmSM4,
	"AES-128": AlgorithmAES128,
	"AES-192": AlgorithmAES192,
	"AES-256": AlgorithmAES256,
	"AES":     AlgorithmAES128, // 默认 AES 归一为 AES-128
	"DES":     AlgorithmDES,
	"3DES":    Algorithm3DES,
	"SM2":     AlgorithmSM2,
	"RSA":     AlgorithmRSA,
	"AES128":  AlgorithmAES128, // 紧凑别名
	"AES192":  AlgorithmAES192,
	"AES256":  AlgorithmAES256,
	"ECDH":    AlgorithmECDH,
	"X25519":  AlgorithmX25519,
	"ECDSA":   AlgorithmECDSA,
	"ED25519": AlgorithmED25519,
}

// NormalizeAlgorithm 将算法名称归一化为标准形式。
// 大小写不敏感；"aes"/"AES" 归一为 "AES-128"；
// "aes128"/"aes-128"/"AES128" 归一为 "AES-128"，同理 192/256；
// "sm4"/"SM4" 归一为 "SM4"；未知算法返回 error。
func NormalizeAlgorithm(name string) (string, error) {
	// 直接精确匹配
	if v, ok := algorithmNameMap[name]; ok {
		return v, nil
	}

	// 尝试大写匹配
	upperName := toUpperASCII(name)
	if v, ok := algorithmNameMap[upperName]; ok {
		return v, nil
	}

	// 别名处理：去除连字符再匹配
	compact := compactName(upperName)
	if v, ok := algorithmNameMap[compact]; ok {
		return v, nil
	}

	return "", fmt.Errorf("unsupported algorithm: %s", name)
}

// toUpperASCII 将字符串中的 ASCII 小写字母转为大写。
func toUpperASCII(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'a' <= c && c <= 'z' {
			c -= 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

// compactName 去除连字符，用于别名匹配（如 "AES128" 匹配 "AES-128"）。
func compactName(s string) string {
	j := 0
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		if b[i] != '-' {
			b[j] = b[i]
			j++
		}
	}
	return string(b[:j])
}
