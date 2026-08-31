package crypto

import (
	"crypto"
	"fmt"

	"github.com/charlienet/go-utils/bytex"
)

// KeyPair 已迁移到 keypair.go
// LegacyKeyPair 已删除：其 Base64 字段可被 encoding/json 直接序列化导致私钥泄露，
// 请使用 KeyPair（含 json:"-" 防护与 MarshalJSON/UnmarshalJSON 禁止）。
// 非对称加密算法
type Asymmetric interface {
	GenerateKey() (KeyPair, error)
	WithPrivateKey(privateKey string) error
	WithPublicKey(publicKey string) error
	ExportPublicKey() (string, error)
	Name() string
	Encrypt(msg []byte) (bytex.Bytes, error)
	Decrypt(ciphertext []byte) (bytex.Bytes, error)
	Signer
}

// Signer 与标准库 crypto.Signer 同名但语义不同，切勿混淆：
//
//   - 本接口：Sign(msg) 直接对完整消息计算签名（内部自行完成哈希），
//     Verify(msg, sign) 同步校验，返回结果便于一步调用；
//   - 标准库 crypto.Signer：Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts)
//     对调用方已哈希的摘要签名并返回原始签名字节，支持哈希与签名分离
//     （如 TLS、离线签名、外部 KMS 等场景）。
//
// 使用本接口的调用方不要将两者混用（例如把消息摘要直接传给本接口的 Sign，
// 或把 crypto.Signer 当作本接口使用）。
type Signer interface {
	Sign(msg []byte) (bytex.Bytes, error)
	Verify(msg, sign []byte) bool
}

// NewAsymmetric 创建非对称算法实例。
// 预定义算法仅支持 RSA/ECDSA/ED25519/SM2（ECDH/X25519 属密钥协商，直接拒绝）；
// 非预定义值（自定义算法/拼写错误）查询注册表，未注册时报
// "no engine registered; import crypto/asym" 错误。
//
// 引擎由 crypto/asym 子包在 init() 中经 RegisterAsymmetricFactory 注册
// （blank import 触发）；未导入时注册表为空，预定义算法同样报 engine 缺失。
func NewAsymmetric(algorithm AsymmetricAlgorithm, opts ...AsymOption) (Asymmetric, error) {
	// 经注册表查询：键为算法名（预定义常量 String() 与 NormalizeAlgorithm 规范形式一致）。
	creator, err := AsymmetricFactoryFor(string(algorithm))
	if err == nil {
		return creator(opts...)
	}

	// 未命中分流：预定义但子集外（密钥协商算法）→ 明确拒绝，无 import 提示；
	// 其余（子集内未导入引擎/非预定义值）→ 提示导入引擎包。
	switch algorithm {
	case ECDH, X25519:
		return nil, fmt.Errorf("unsupported asymmetric algorithm: %s", algorithm)
	default:
		return nil, fmt.Errorf("no engine registered for %s; add blank import: _ \"github.com/charlienet/go-crypto/asym\" or _ \"github.com/charlienet/go-crypto/engines\" for all: %w", algorithm, ErrEngineNotRegistered)
	}
}

// AsymConfig 非对称构造选项目标。构造期使用，选项仅应用一次，
// 构造完成后不再被读取，调用方不得跨构造复用。
// 字符串密钥（PublicKey/PrivateKey）为 base64 DER 编码；
// 对象密钥（PublicKeyObject/PrivateKeyObject）为 crypto.PublicKey/crypto.PrivateKey 实现。
type AsymConfig struct {
	PublicKey        string
	PrivateKey       string
	PublicKeyObject  crypto.PublicKey
	PrivateKeyObject crypto.PrivateKey
}

// AsymOption 非对称构造选项函数。返回 error：选项在构造期可失败，
// 与对称 Option（无返回值）语义不同。
type AsymOption func(*AsymConfig) error

// WithPublicKey 以 base64 DER 公钥字符串注入公钥
func WithPublicKey(publicKey string) AsymOption {
	return func(cfg *AsymConfig) error {
		cfg.PublicKey = publicKey
		return nil
	}
}

// WithPrivateKey 以 base64 DER 私钥字符串注入私钥
func WithPrivateKey(privateKey string) AsymOption {
	return func(cfg *AsymConfig) error {
		cfg.PrivateKey = privateKey
		return nil
	}
}

// WithPrivateKeyObject 使用密钥对象创建非对称加密器
func WithPrivateKeyObject(key crypto.PrivateKey) AsymOption {
	return func(cfg *AsymConfig) error {
		cfg.PrivateKeyObject = key
		return nil
	}
}

// WithPublicKeyObject 使用密钥对象创建非对称加密器
func WithPublicKeyObject(key crypto.PublicKey) AsymOption {
	return func(cfg *AsymConfig) error {
		cfg.PublicKeyObject = key
		return nil
	}
}
