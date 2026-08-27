package kdf

import (
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"

	"golang.org/x/crypto/pbkdf2"
)

// PBKDF2 基于密码的密钥派生函数（RFC 2898）。
//
// 参数：
//   - password：用户密码
//   - salt：盐值（建议至少 16 字节随机值，每次派生唯一）
//   - iterations：迭代次数（建议 ≥ 100000，根据硬件性能调整）
//   - keyLen：输出密钥长度（字节）
//
// 返回：
//   - 派生密钥（长度 keyLen）
//   - 错误（当前实现始终返回 nil，保留用于未来扩展）
//
// 使用场景：
//   - 从用户密码派生加密密钥
//   - 兼容遗留系统（广泛使用的标准）
//
// 安全建议：
//   - 迭代次数越高越安全，但性能开销越大
//   - 新系统推荐使用 Argon2id（内存硬，抗 GPU 攻击）
//   - Salt 必须唯一且随机
//
// 示例：
//
//	key, _ := kdf.PBKDF2([]byte("password"), salt, 100000, 16)
//	// key: 16 字节 AES-128 密钥
func PBKDF2(password, salt []byte, iterations, keyLen int) ([]byte, error) {
	if iterations <= 0 {
		return nil, errors.New("kdf: iterations must be positive")
	}
	if keyLen <= 0 {
		return nil, errors.New("kdf: keyLen must be positive")
	}

	// 默认使用 SHA-256
	return pbkdf2.Key(password, salt, iterations, keyLen, sha256.New), nil
}

// PBKDF2WithHash 使用指定哈希算法的 PBKDF2。
//
// 参数：
//   - hash：哈希算法名称（"SHA-256"、"SHA-384"、"SHA-512"）
//   - 其他参数同 PBKDF2
//
// 示例：
//
//	key, _ := kdf.PBKDF2WithHash("SHA-512", []byte("password"), salt, 100000, 32)
func PBKDF2WithHash(hashAlg string, password, salt []byte, iterations, keyLen int) ([]byte, error) {
	if iterations <= 0 {
		return nil, errors.New("kdf: iterations must be positive")
	}
	if keyLen <= 0 {
		return nil, errors.New("kdf: keyLen must be positive")
	}

	var h func() hash.Hash
	switch hashAlg {
	case "SHA-256", "SHA256":
		h = sha256.New
	case "SHA-384", "SHA384":
		h = sha512.New384
	case "SHA-512", "SHA512":
		h = sha512.New
	default:
		return nil, errors.New("kdf: unsupported hash algorithm: " + hashAlg)
	}

	return pbkdf2.Key(password, salt, iterations, keyLen, h), nil
}
