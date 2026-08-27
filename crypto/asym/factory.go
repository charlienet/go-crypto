package asym

import (
	"fmt"

	"github.com/charlienet/go-crypto/crypto"
)

// Option 是 asym 子包直接工厂的选项别名（与根包 AsymOption 同型），
// 调用方无需显式 import 根包即可传入选项。
type Option = crypto.AsymOption

// New 创建非对称算法实例（子包直接工厂）：直发包内构造器，不经注册表。
// 预定义四算法（RSA/ECDSA/ED25519/SM2）与根包 NewAsymmetric 行为一致；
// 子集外（ECDH/X25519）与非预定义值返回 "unsupported asymmetric algorithm: %s"。
func New(algorithm crypto.AsymmetricAlgorithm, opts ...Option) (crypto.Asymmetric, error) {
	switch algorithm {
	case crypto.RSA:
		return newRSA(opts...)
	case crypto.ECDSA:
		return newECDSA(opts...)
	case crypto.ED25519:
		return newED25519(opts...)
	case crypto.SM2:
		return newSM2(opts...)
	default:
		return nil, fmt.Errorf("unsupported asymmetric algorithm: %s", algorithm)
	}
}
