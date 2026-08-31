package agreement

import (
	"crypto"
	"errors"

	rootcrypto "github.com/charlienet/go-crypto"
	"github.com/charlienet/go-crypto/common"
	"github.com/charlienet/go-crypto/kdf"
)

// DeriveKey 一步式密钥协商派生助手：从协商器派生共享密钥并立即经
// HKDF("SHA-256") 扩展为 keyLen 字节密钥。
//
// 协商器若实现 rootcrypto.KeyDeriver（可选扩展接口，见根包
// keyagreement.go）则优先调用其 DeriveKey；否则回退为
// DeriveSharedSecret → HKDF → 及时清零中间共享秘密（敏感密钥材料）。
// SM2 协商的 DeriveSharedSecret 已禁用，经回退路径自然返回既有哨兵错误。
//
// 注意：与 kdf.DeriveKey（Argon2id 口令派生）同名不同义——
// 本函数处理协商共享密钥（HKDF 扩展），误用会得到语义完全不同的输出。
// 对端公钥必须来自认证通道。
func DeriveKey(ka rootcrypto.KeyAgreement, peer crypto.PublicKey, salt, info []byte, keyLen int) ([]byte, error) {
	if keyLen <= 0 {
		return nil, errors.New("agreement: keyLen must be positive")
	}

	// 可选扩展接口优先：协商器自实现派生语义（如未来 SM2 KAP）
	if kd, ok := ka.(rootcrypto.KeyDeriver); ok {
		return kd.DeriveKey(peer, salt, info, keyLen)
	}

	secret, err := ka.DeriveSharedSecret(peer)
	if err != nil {
		return nil, err
	}
	// 中间共享秘密是敏感密钥材料，派生完成立即清零（nil 为安全操作）
	defer common.ZeroBytes(secret)

	return kdf.HKDF("SHA-256", secret, salt, info, keyLen)
}