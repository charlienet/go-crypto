package crypto

import (
	"crypto"
	"fmt"
)

// KeyAgreementAlgorithm 密钥协商算法枚举。
// 与 AsymmetricAlgorithm 底层类型相同（string），值可互转。
// 预定义值：ECDH / X25519 / SM2。
//
// 使用类型别名而非独立类型，保持与 AsymmetricAlgorithm 的兼容性，
// 同时提供更精确的语义。调用方可选择使用更精确的类型名：
//
//	var alg crypto.KeyAgreementAlgorithm = crypto.ECDH
//	ka, _ := crypto.NewKeyAgreement(alg)
type KeyAgreementAlgorithm = AsymmetricAlgorithm

// KeyAgreement 密钥协商接口。
//
// 并发安全说明：本接口实现（ECDH/X25519/SM2）均非并发安全，
// 每个实例应在单协程内使用；GenerateKey 与 WithPrivateKey 写入同一
// 私钥字段，二者互斥，重复调用以后一次为准。
//
// 注意：SM2 实现的 DeriveSharedSecret 已被禁用（始终返回错误），
// 因其原实现为裸标量乘法拼接 x||y，并非标准 SM2 KAP——
// 无前向保密、无 SM3-KDF、无密钥确认、输出长度不稳定（63/64 字节浮动），极易误用。
// 需要 SM2 曲线上的协商时，请改用 ECDH 或 X25519。
type KeyAgreement interface {
	GenerateKey() (*KeyPair, error)
	// WithPrivateKey 注入既有私钥（密钥轮换/存量密钥导入场景），
	// 语义与 asymmetric 包的 WithPrivateKeyObject 一致。
	// 注入后 DeriveSharedSecret 使用该私钥；与 GenerateKey 互斥（写同一字段）。
	WithPrivateKey(key crypto.PrivateKey) error
	// DeriveSharedSecret 返回原始共享密钥，未经任何 KDF 派生。
	// 用作对称密钥材料前，必须经 HKDF/SM3-KDF 等密钥派生函数处理；
	// 对端公钥必须来自认证通道，防止中间人替换。
	DeriveSharedSecret(peerPublicKey crypto.PublicKey) ([]byte, error)
	Name() string
}

// KeyDeriver 一步式密钥派生协商的可选扩展接口。
//
// 实现 KeyAgreement 的协商器可选择性实现本接口，在 DeriveSharedSecret
// 之上提供"共享秘密 + KDF"的一体化派生语义（如未来的 SM2 KAP 可实现
// 标准密钥确认派生）；当前内置协商器（ECDH/X25519/SM2）均未实现，
// 调用方使用 agreement.DeriveKey 时会经该断言，未命中则走通用回退
// （DeriveSharedSecret → HKDF-SHA256 → 及时清零中间秘密）。
type KeyDeriver interface {
	// DeriveKey 从协商的共享秘密一步派生 keyLen 字节密钥。
	// 对端公钥必须来自认证通道，防止中间人替换；salt/info 用于域分离。
	DeriveKey(peer crypto.PublicKey, salt, info []byte, keyLen int) ([]byte, error)
}

// NewKeyAgreement 创建密钥协商器。
// 预定义算法仅支持 ECDH/X25519/SM2（RSA/ECDSA/ED25519 属非对称加解密，直接拒绝）；
// 非预定义值（自定义算法/拼写错误）查询注册表，未注册时报
// "no engine registered; import crypto/agreement" 错误。
//
// 参数类型为 KeyAgreementAlgorithm（AsymmetricAlgorithm 的别名），语义更精确。
// 调用方可选择使用更精确的类型名：
//
//	var alg crypto.KeyAgreementAlgorithm = crypto.ECDH
//	ka, _ := crypto.NewKeyAgreement(alg)
func NewKeyAgreement(algorithm KeyAgreementAlgorithm) (KeyAgreement, error) {
	creator, err := KeyAgreementFactoryFor(string(algorithm))
	if err == nil {
		return creator()
	}
	switch algorithm {
	case RSA, ECDSA, ED25519:
		return nil, fmt.Errorf("unsupported key agreement algorithm: %s", algorithm)
	default:
		return nil, fmt.Errorf("no engine registered for %s; add blank import: _ \"github.com/charlienet/go-crypto/agreement\" or _ \"github.com/charlienet/go-crypto/engines\" for all: %w", algorithm, ErrEngineNotRegistered)
	}
}
