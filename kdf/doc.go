// Package kdf 提供密钥派生函数（Key Derivation Function）。
//
// KDF 用于从低熵输入（如密码）派生出高熵的加密密钥，或从一个主密钥派生出多个子密钥。
//
// # 算法选择
//
//   - HKDF：密钥扩展场景（从共享密钥派生多个子密钥），基于 HMAC，快速
//   - PBKDF2：密码派生场景（从用户密码派生加密密钥），迭代哈希，兼容性好
//   - Argon2id：密码派生场景（新系统推荐），内存硬，抗 GPU/ASIC 攻击
//
// # 使用示例
//
// 密码派生（推荐 Argon2id）：
//
//	key, err := kdf.Argon2id([]byte("password"), salt, 3, 64*1024, 4, 16)
//	// key: 16 字节 AES-128 密钥
//
// 密钥扩展（HKDF）：
//
//	encKey, _ := kdf.HKDF("SHA-256", sharedSecret, nil, []byte("encryption"), 16)
//	authKey, _ := kdf.HKDF("SHA-256", sharedSecret, nil, []byte("authentication"), 32)
//
// 高层便捷入口（自动选择算法）：
//
//	key, err := kdf.DeriveKey([]byte("password"), salt, 16)
//	// 内部使用 Argon2id，适合大多数场景
//
// # 与 crypto 包集成
//
//	import (
//	    crypto "github.com/charlienet/go-crypto"
//	    "github.com/charlienet/go-crypto/kdf"
//	)
//
//	// 从密码派生 AES-128 密钥
//	key, _ := kdf.Argon2id([]byte("user-password"), salt, 3, 64*1024, 4, 16)
//	ct, _ := crypto.Encrypt(crypto.AES128, crypto.GCM, plaintext, crypto.WithKey(key))
//
// # 安全建议
//
//   - 密码派生：优先 Argon2id（新系统）或 PBKDF2（兼容遗留）
//   - Salt：至少 16 字节随机值，每次派生唯一
//   - 迭代次数/内存：根据硬件性能调整，建议 PBKDF2 ≥ 600000 次
//     （OWASP 2024 密码存储建议，HMAC-SHA256 不低于 600,000 次，
//     与 keymgr/pbes2.go 的 pbes2PBKDF2Iterations=600_000 一致），
//     Argon2id 内存 ≥ 64MB
//   - Info 字段（HKDF）：用于区分不同用途的密钥，防止密钥混淆攻击
package kdf
