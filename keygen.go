package crypto

import "fmt"

// GenerateKeyPair 生成指定算法的密钥对。
// 预定义算法仅支持 RSA/ECDSA/ED25519/SM2（ECDH/X25519 属密钥协商，直接拒绝）；
// 非预定义值（自定义算法/拼写错误）查询注册表，未注册时报
// "no engine registered; import crypto/keymgr" 错误。
//
// 算法实现位于 crypto/keymgr 子包，经注册表分发：使用前须 blank import
// 该子包（或经 RegisterKeyPairGenerator 显式注册）。
func GenerateKeyPair(algorithm AsymmetricAlgorithm, opts ...KeyGenOption) (*KeyPair, error) {
	gen, err := KeyPairGeneratorFor(string(algorithm))
	if err == nil {
		cfg := &KeyGenConfig{KeySize: 2048, Curve: "P256"}
		for _, opt := range opts {
			opt(cfg)
		}
		return gen(cfg)
	}
	switch algorithm {
	case ECDH, X25519:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	default:
		return nil, fmt.Errorf("no engine registered for %s; add blank import: _ \"github.com/charlienet/go-crypto/keymgr\" or _ \"github.com/charlienet/go-crypto/engines\" for all: %w", algorithm, ErrEngineNotRegistered)
	}
}
