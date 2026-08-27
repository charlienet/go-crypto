package kdf

import (
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
	"io"

	"golang.org/x/crypto/hkdf"
)

// HKDF 基于 HMAC 的密钥派生函数（RFC 5869）。
//
// 参数：
//   - hash：哈希算法名称（"SHA-256"、"SHA-384"、"SHA-512"）
//   - secret：输入密钥材料（IKM），如共享密钥
//   - salt：可选盐值（nil 或空切片使用哈希长度零串）
//   - info：可选上下文信息，用于区分不同用途的密钥
//   - keyLen：输出密钥长度（字节）
//
// 返回：
//   - 派生密钥（长度 keyLen）
//   - 错误（不支持的哈希算法、输出长度超限等）
//
// 使用场景：
//   - 从共享密钥派生多个子密钥（如加密密钥 + 认证密钥）
//   - 密钥扩展（从短密钥派生长密钥）
//
// 示例：
//
//	encKey, _ := kdf.HKDF("SHA-256", sharedSecret, nil, []byte("encryption"), 16)
//	authKey, _ := kdf.HKDF("SHA-256", sharedSecret, nil, []byte("authentication"), 32)
func HKDF(hashAlg string, secret, salt, info []byte, keyLen int) ([]byte, error) {
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

	hkdfReader := hkdf.New(h, secret, salt, info)
	key := make([]byte, keyLen)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, err
	}
	return key, nil
}
