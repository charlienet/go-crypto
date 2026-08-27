package kdf

import (
	"errors"
)

// DeriveKey 高层便捷入口，从密码派生指定长度的密钥。
//
// 内部使用 Argon2id（默认参数），适合大多数密码派生场景。
// 如需自定义参数或使用其他算法，请直接调用 Argon2id / PBKDF2 / HKDF。
//
// 参数：
//   - password：用户密码
//   - salt：盐值（建议至少 16 字节随机值，每次派生唯一）
//   - keyLen：输出密钥长度（字节）
//
// 返回：
//   - 派生密钥（长度 keyLen）
//   - 错误（参数非法时返回错误）
//
// 示例：
//
//	key, _ := kdf.DeriveKey([]byte("password"), salt, 16)
//	// key: 16 字节 AES-128 密钥
func DeriveKey(password, salt []byte, keyLen int) ([]byte, error) {
	if keyLen <= 0 {
		return nil, errors.New("kdf: keyLen must be positive")
	}
	if len(salt) == 0 {
		return nil, errors.New("kdf: salt must not be empty")
	}
	return Argon2idDefault(password, salt, keyLen)
}
