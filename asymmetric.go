package crypto

import (
	"crypto"
	"errors"
	"fmt"
	"strings"

	"github.com/charlienet/go-utils/bytex"
)

// ErrInvalidAsymOption 非对称选项参数非法时返回的统一哨兵（包装错误消息
// 附具体参数细节）。选项返回 error（AsymOption 签名），在工厂构造入口
// 应用选项时即被拒绝，未消费非法配置的实例。
var ErrInvalidAsymOption = errors.New("crypto: invalid asymmetric option")

// KeyPair 已迁移到 keypair.go
// LegacyKeyPair 已删除：其 Base64 字段可被 encoding/json 直接序列化导致私钥泄露，
// 请使用 KeyPair（含 json:"-" 防护与 MarshalJSON/UnmarshalJSON 禁止）。
// 非对称加密算法
//
// 注意：GenerateKey / WithPrivateKey（含对象与字符串注入路径）成功设置
// 私钥后，同实例的公钥能力自动派生（puk 回填），可直接调用 Verify 验签
// 与 Encrypt 加密，无需另行注入公钥。
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
//
// 参数默认值（0 值 → 默认）由各算法实现消费时归一：
//   - RSAKeyBits：0 → 2048；经 WithRSAKeyBits 显式传 <2048 在选项应用期拒绝
//   - ECDSACurve："" → P256（经 WithECDSACurve 显式传非白名单值拒绝）
//   - Hash：0 → SHA256（经 WithAsymHash 显式传白名单外摘要算法拒绝；
//     SHA-1 属构造期闸门控制项，应用期放行、由算法实现在构造期经
//     AllowInsecure 判定，不再是"白名单外即拒"）
//   - SM2UID：nil → gmsm 默认 UID（经 WithSM2UID 显式覆盖）
//   - SM2LegacyCipher：false → 使用新认证密文格式（C1C3C2）；true → 遗留
//     非认证格式（C1C2C3），仅对接遗留系统时启用
type AsymConfig struct {
	PublicKey        string
	PrivateKey       string
	PublicKeyObject  crypto.PublicKey
	PrivateKeyObject crypto.PrivateKey

	// RSAKeyBits RSA 密钥位数。0 → 2048（默认）；显式传值必须 >=2048。
	RSAKeyBits int
	// ECDSACurve ECDSA 曲线名。"" → P256；白名单 P256/P384/P521
	//（输入大小写不敏感、忽略连字符，存储为规范形式 "P256"/"P384"/"P521"）。
	ECDSACurve string
	// Hash 签名摘要算法。0 → SHA256；白名单 SHA-1/SHA-256/SHA-384/SHA-512
	//（SHA-1 为不安全项，构造期须经 AllowInsecure 闸门放行，仅 RSA 支持）。
	Hash crypto.Hash
	// SM2UID SM2 用户标识。nil → gmsm 库默认 UID（"1234567812345678"）。
	SM2UID []byte
	// SM2LegacyCipher 使用 SM2 遗留非认证密文格式（C1C2C3）。
	// 默认 false：新认证格式（C1C3C2）。仅对接遗留系统时启用。
	SM2LegacyCipher bool
	// RSASignPKCS1v15 RSA 签名/验签使用 PKCS#1 v1.5 填充（默认 PSS）。
	// 仅影响 Sign/Verify，加密（Encrypt/Decrypt）始终使用 OAEP；
	// 仅遗留系统互操作时启用。
	RSASignPKCS1v15 bool
	// AllowInsecure 放行不安全配置（WithAsymInsecureAlgorithms()）。
	// 当前覆盖 RSA 签名 SHA-1 摘要（构造期闸门判定）。
	AllowInsecure bool
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

// 曲线白名单：ECDSA 支持的标准曲线（P-224 因安全性不足被禁用）。
// 键为去掉连字符并大写后的规范名，输入经同样归一化后匹配。
var ecdsaCurveWhitelist = map[string]struct{}{
	"P256": {},
	"P384": {},
	"P521": {},
}

// normalizeCurveName 将曲线名归一为规范形式（去连字符、大写，
// 如 "p-256"/"P_256" → "P256"）；空串原样返回（表示走默认值）。
func normalizeCurveName(curve string) string {
	return strings.ToUpper(strings.ReplaceAll(curve, "-", ""))
}

// WithRSAKeyBits 设置 RSA 密钥位数（默认 2048）。
// 显式传值必须 >=2048（小于 2048 已在选项应用期拒绝，返回
// ErrInvalidAsymOption）；0 表示走默认值。与 GenerateKeyPair 的
// KeyGenOption.WithKeySize 语义一致，两者互不干扰（本选项作用于
// AsymConfig 构造路径）。
func WithRSAKeyBits(bits int) AsymOption {
	return func(cfg *AsymConfig) error {
		if bits != 0 && bits < 2048 {
			return fmt.Errorf("%w: RSA key bits %d below minimum 2048", ErrInvalidAsymOption, bits)
		}
		cfg.RSAKeyBits = bits
		return nil
	}
}

// WithECDSACurve 设置 ECDSA 曲线名称。
// 白名单：P256 / P384 / P521（P-224 已禁用）；大小写不敏感、忽略连字符，
// 存储为规范形式（"P256" 等）。"" 表示走默认 P256。非法曲线在选项应用期
// 返回 ErrInvalidAsymOption。与 GenerateKeyPair 的 KeyGenOption.WithCurve
// 语义一致，两者互不干扰（本选项作用于 AsymConfig 构造路径）。
func WithECDSACurve(curve string) AsymOption {
	return func(cfg *AsymConfig) error {
		if curve == "" {
			cfg.ECDSACurve = ""
			return nil
		}
		norm := normalizeCurveName(curve)
		if _, ok := ecdsaCurveWhitelist[norm]; !ok {
			return fmt.Errorf("%w: unsupported ECDSA curve %q (whitelist: P256/P384/P521)", ErrInvalidAsymOption, curve)
		}
		cfg.ECDSACurve = norm
		return nil
	}
}

// WithAsymHash 设置签名摘要算法（默认 SHA256）。
// 白名单：SHA-1/SHA-256/SHA-384/SHA-512；0 表示走默认。白名单外值
// （MD5/MD5SHA1 等）返回 ErrInvalidAsymOption。
// SHA-1 属不安全摘要：应用期仅接受写入配置，安全性判定延迟到构造期
// 闸门——仅 RSA 支持，且须经 WithAsymInsecureAlgorithms() 放行，否则
// 构造时返回 ErrInsecureAlgorithm；选项顺序无关（判定在构造期统一进行）。
// 命名用 AsymHash 前缀以区别于 keypair.go 的
// KeyGenOption（KeyGenOption 无对应哈希选项，预留命名空间避免未来混淆）。
func WithAsymHash(h crypto.Hash) AsymOption {
	return func(cfg *AsymConfig) error {
		if h == 0 {
			cfg.Hash = 0
			return nil
		}
		switch h {
		case crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512:
			cfg.Hash = h
			return nil
		}
		return fmt.Errorf("%w: unsupported hash %v (whitelist: SHA1/SHA256/SHA384/SHA512; SHA-1 须经 WithAsymInsecureAlgorithms() 构造期放行)", ErrInvalidAsymOption, h)
	}
}

// WithSM2UID 设置 SM2 用户标识 UID（内部拷贝保存）。
// nil/未设置 → gmsm 默认 UID（"1234567812345678"）。与 gmsm 对接时，
// 若对端使用非默认 UID，必须显式传入相同 UID，否则签名校验失败。
func WithSM2UID(uid []byte) AsymOption {
	return func(cfg *AsymConfig) error {
		cfg.SM2UID = append([]byte(nil), uid...)
		return nil
	}
}

// WithSM2LegacyCiphertext 使用 SM2 遗留非认证密文格式（C1C2C3）。
// 默认使用新认证格式（C1C3C2，密文携带 SM3 摘要可检测篡改）；
// 仅对接使用遗留格式的系统时启用本选项。
func WithSM2LegacyCiphertext() AsymOption {
	return func(cfg *AsymConfig) error {
		cfg.SM2LegacyCipher = true
		return nil
	}
}

// WithRSAPKCS1v15Signing RSA 签名/验签使用 PKCS#1 v1.5 填充（默认 PSS）。
// 仅影响 RSA 的 Sign/Verify，Encrypt/Decrypt 始终使用 OAEP 不受本选项
// 影响；填充格式切换属格式兼容开关，不涉及安全闸门。仅遗留系统互操作
// （对端仅支持 RSASSA-PKCS1-v1_5 签名）时启用。
func WithRSAPKCS1v15Signing() AsymOption {
	return func(cfg *AsymConfig) error {
		cfg.RSASignPKCS1v15 = true
		return nil
	}
}

// WithAsymInsecureAlgorithms 放行不安全非对称配置（与对称侧
// WithInsecureAlgorithms 同风格的安全闸门）。
//
// 默认情况下，以下配置被拒绝（构造期返回 ErrInsecureAlgorithm）：
//   - RSA 签名摘要算法 SHA-1（碰撞攻击实用化，仅限遗留系统互操作）
//
// 判定在构造期（工厂消费配置时）进行，与选项书写顺序无关；
// 仅在对接遗留系统时必须使用，新代码应使用 SHA-256 及以上摘要。
func WithAsymInsecureAlgorithms() AsymOption {
	return func(cfg *AsymConfig) error {
		cfg.AllowInsecure = true
		return nil
	}
}
