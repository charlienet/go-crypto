package agreement

import (
	"fmt"

	"github.com/charlienet/go-crypto/crypto"
)

// New 创建密钥协商实例（子包直接工厂）：直发包内构造器，不经注册表。
// 预定义三算法（ECDH/X25519/SM2）与根包 NewKeyAgreement 行为一致；
// 子集外（RSA/ECDSA/ED25519）与非预定义值返回 "unsupported key agreement algorithm: %s"。
func New(algorithm crypto.AsymmetricAlgorithm) (crypto.KeyAgreement, error) {
	switch algorithm {
	case crypto.ECDH:
		return newECDH()
	case crypto.X25519:
		return newX25519()
	case crypto.SM2:
		return newSM2KeyAgreement()
	default:
		return nil, fmt.Errorf("unsupported key agreement algorithm: %s", algorithm)
	}
}
