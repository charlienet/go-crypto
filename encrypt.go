package crypto

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// nonceSize 标准 GCM nonce 长度（协议层 IV/nonce 长度校验用，固定 12 字节）。
const nonceSize = 12

// Algorithm 对称加密算法枚举（模式化 API 专用）。
// String() 输出与 NormalizeAlgorithm 规范形式一致，可桥接 NewCipher/envelope 层。
type Algorithm uint8

const (
	AES128    Algorithm = iota + 1 // 密钥严格 16B
	AES192                         // 密钥严格 24B
	AES256                         // 密钥严格 32B
	SM4                            // 密钥严格 16B
	DES                            // 密钥 8B，仅遗留兼容；仅 ECB/CBC/CTR/CFB/OFB，不支持 GCM
	TripleDES                      // 密钥 24B（3DES 为非法标识符，故命名 TripleDES），约束同 DES
)

// String 返回算法规范名（AES128→"AES-128"、TripleDES→"3DES"、其余同名）。
// 输出与 NormalizeAlgorithm 一致，可直接传入 NewCipher 与 envelope 子包。
func (a Algorithm) String() string {
	switch a {
	case AES128:
		return "AES-128"
	case AES192:
		return "AES-192"
	case AES256:
		return "AES-256"
	case SM4:
		return "SM4"
	case DES:
		return "DES"
	case TripleDES:
		return "3DES"
	default:
		return fmt.Sprintf("Algorithm(%d)", a)
	}
}

// BlockSize 返回块大小（AES*/SM4=16，DES/TripleDES=8），用于 IV/计数器长度推导。
func (a Algorithm) BlockSize() int {
	switch a {
	case AES128, AES192, AES256, SM4:
		return 16
	case DES, TripleDES:
		return 8
	default:
		return 0
	}
}

// KeySize 返回算法严格密钥长度（16/24/32/16/8/24）。
func (a Algorithm) KeySize() int {
	switch a {
	case AES128, SM4:
		return 16
	case AES192, TripleDES:
		return 24
	case AES256:
		return 32
	case DES:
		return 8
	default:
		return 0
	}
}

// Mode 分组加密工作模式枚举。
type Mode uint8

const (
	ECB Mode = iota + 1 // 无 IV；不安全，仅遗留兼容
	CBC                 // IV=块大小，前置/外部持有
	CTR                 // 计数器=块大小；无认证
	CFB                 // IV=块大小
	OFB                 // IV=块大小
	GCM                 // nonce=12B，认证加密（推荐）
)

// String 返回模式名（"ECB"/"CBC"/"CTR"/"CFB"/"OFB"/"GCM"）。
func (m Mode) String() string {
	switch m {
	case ECB:
		return "ECB"
	case CBC:
		return "CBC"
	case CTR:
		return "CTR"
	case CFB:
		return "CFB"
	case OFB:
		return "OFB"
	case GCM:
		return "GCM"
	default:
		return fmt.Sprintf("Mode(%d)", m)
	}
}

// algorithmNames 规范名（去连字符、转大写后）→ 算法枚举。
var algorithmNames = map[string]Algorithm{
	"AES128":    AES128,
	"AES192":    AES192,
	"AES256":    AES256,
	"SM4":       SM4,
	"DES":       DES,
	"3DES":      TripleDES,
	"TRIPLEDES": TripleDES,
}

// ParseAlgorithm 解析算法名：大小写不敏感、忽略连字符。
// "aes-128"/"AES128"/"3des"/"tripledes" 均接受；未知名称返回 ErrUnknownAlgorithm。
// 保证 ParseAlgorithm(a.String()) == a。
func ParseAlgorithm(s string) (Algorithm, error) {
	if a, ok := algorithmNames[strings.ToUpper(strings.ReplaceAll(s, "-", ""))]; ok {
		return a, nil
	}
	return 0, ErrUnknownAlgorithm
}

// modeNames 规范名 → 模式枚举。
var modeNames = map[string]Mode{
	"ECB": ECB,
	"CBC": CBC,
	"CTR": CTR,
	"CFB": CFB,
	"OFB": OFB,
	"GCM": GCM,
}

// ParseMode 解析模式名：大小写不敏感、忽略连字符；未知名称返回 ErrUnknownMode。
// 保证 ParseMode(m.String()) == m。
func ParseMode(s string) (Mode, error) {
	if m, ok := modeNames[strings.ToUpper(strings.ReplaceAll(s, "-", ""))]; ok {
		return m, nil
	}
	return 0, ErrUnknownMode
}

// 模式化加解密 API 的哨兵错误。
var (
	ErrUnknownAlgorithm          = errors.New("crypto: unknown algorithm")
	ErrUnknownMode               = errors.New("crypto: unknown mode")
	ErrIncompatibleAlgorithmMode = errors.New("crypto: algorithm does not support this mode")
	ErrInvalidIVLength           = errors.New("crypto: invalid IV length")
	ErrInvalidNonceLength        = errors.New("crypto: invalid nonce length, want 12 bytes")
	ErrNonceNotSupported         = errors.New("crypto: nonce only supported for GCM")
	ErrIVNotSupported            = errors.New("crypto: IV not supported for this mode")
	ErrPaddingNotSupported       = errors.New("crypto: padding not supported for this mode")
	ErrAADNotSupported           = errors.New("crypto: AAD only supported for GCM")
	ErrKeyRequired               = errors.New("crypto: key required (WithKey/WithKeyPassword/WithHexPassword/WithBase64Password)")
	ErrInvalidHexPassword        = errors.New("crypto: invalid hex password")
	ErrInvalidBase64Password     = errors.New("crypto: invalid base64 password")
	ErrInvalidHexIV              = errors.New("crypto: invalid hex IV")
	ErrInvalidBase64IV           = errors.New("crypto: invalid base64 IV")
	ErrInvalidHexNonce           = errors.New("crypto: invalid hex nonce")
	ErrInvalidBase64Nonce        = errors.New("crypto: invalid base64 nonce")
	ErrAuthenticationFailed      = errors.New("crypto: message authentication failed")
	ErrInsecureAlgorithm         = errors.New("crypto: insecure algorithm/mode refused (DES/3DES/ECB); use WithInsecureAlgorithms() to override")
)

// WithKey 以原始密钥字节提供密钥（内部拷贝保存）。
// 密钥长度必须与算法严格匹配（AES128=16、AES192=24、AES256=32、SM4=16、DES=8、TripleDES=24）。
// 多个选项按调用顺序覆盖，后调用的选项会覆盖先调用的选项。
func WithKey(key []byte) Option {
	return func(cfg *Config) {
		cfg.Key = append([]byte(nil), key...)
	}
}

// WithKeyPassword 将字符串直接作为密钥字节（[]byte(password)，无 KDF）。
// 仅适用于 ASCII/可打印文本密钥；二进制密钥请使用 WithKey 或 WithHexPassword/WithBase64Password。
// 多个选项按调用顺序覆盖，后调用的选项会覆盖先调用的选项。
func WithKeyPassword(password string) Option {
	return func(cfg *Config) {
		cfg.Key = []byte(password)
	}
}

// WithHexPassword 将 hex 字符串解码为密钥字节；
// 解码失败由 Encrypt/Decrypt 返回 ErrInvalidHexPassword。
// 多个选项按调用顺序覆盖，后调用的选项会覆盖先调用的选项。
func WithHexPassword(hexEncoded string) Option {
	return func(cfg *Config) {
		key, err := hex.DecodeString(hexEncoded)
		if err != nil {
			cfg.KeyError = ErrInvalidHexPassword
			return
		}
		cfg.Key = key
	}
}

// WithBase64Password 将 Base64（StdEncoding）字符串解码为密钥字节；
// 解码失败由 Encrypt/Decrypt 返回 ErrInvalidBase64Password。
// 多个选项按调用顺序覆盖，后调用的选项会覆盖先调用的选项。
func WithBase64Password(base64Encoded string) Option {
	return func(cfg *Config) {
		key, err := base64.StdEncoding.DecodeString(base64Encoded)
		if err != nil {
			cfg.KeyError = ErrInvalidBase64Password
			return
		}
		cfg.Key = key
	}
}

// WithIV 外部提供 IV（或 CTR 计数器）：密文不含前缀。
// 适用 CBC/CFB/OFB/CTR，长度必须等于算法块大小；ECB 与 GCM 传 IV 返回 ErrIVNotSupported。
// 解密时必须对称传入同一 IV，否则无法解密。
// 传入 nil 等价于未提供该选项：走默认随机生成 + 前置路径。
//
// 安全警告：固定 IV 下同一密钥加密多条消息会复用 keystream
// （C1⊕C2 = P1⊕P2 直接泄露明文）。默认（不传此选项）每次加密随机
// 生成 IV 并前置，推荐使用。
func WithIV(iv []byte) Option {
	return func(cfg *Config) {
		cfg.IV = append([]byte(nil), iv...)
		cfg.IVError = nil  // 清除前者的解码错误
	}
}

// WithNonce 外部提供 GCM nonce：密文不含前缀，长度必须 12 字节。
// 仅 GCM 支持；其他模式传入返回 ErrNonceNotSupported，长度非 12 返回 ErrInvalidNonceLength。
// 解密时必须对称传入同一 nonce。
// 传入 nil 等价于未提供该选项：走默认随机生成 + 前置路径。
//
// 安全警告：固定 nonce 下同一密钥加密两条消息即导致 GCM 机密性完全丧失
// （keystream 异或消去，直接泄露明文异或）。默认（不传此选项）每次加密
// 随机生成 nonce 并前置，推荐使用。
func WithNonce(nonce []byte) Option {
	return func(cfg *Config) {
		cfg.Nonce = append([]byte(nil), nonce...)
		cfg.NonceError = nil  // 清除前者的解码错误
	}
}

// WithHexIV 将 hex 字符串解码为 IV 字节；
// 解码失败由 Encrypt/Decrypt 返回 ErrInvalidHexIV。
// 语义与 WithIV 相同，多个 IV 选项按调用顺序后者覆盖前者。
func WithHexIV(hexString string) Option {
	return func(cfg *Config) {
		iv, err := hex.DecodeString(hexString)
		if err != nil {
			cfg.IVError = ErrInvalidHexIV
			return
		}
		cfg.IV = iv
		cfg.IVError = nil
	}
}

// WithBase64IV 将 Base64（StdEncoding）字符串解码为 IV 字节；
// 解码失败由 Encrypt/Decrypt 返回 ErrInvalidBase64IV。
// 语义与 WithIV 相同，多个 IV 选项按调用顺序后者覆盖前者。
func WithBase64IV(encoded string) Option {
	return func(cfg *Config) {
		iv, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			cfg.IVError = ErrInvalidBase64IV
			return
		}
		cfg.IV = iv
		cfg.IVError = nil
	}
}

// WithHexNonce 将 hex 字符串解码为 GCM nonce 字节；
// 解码失败由 Encrypt/Decrypt 返回 ErrInvalidHexNonce。
// 语义与 WithNonce 相同，多个 nonce 选项按调用顺序后者覆盖前者。
func WithHexNonce(hexString string) Option {
	return func(cfg *Config) {
		nonce, err := hex.DecodeString(hexString)
		if err != nil {
			cfg.NonceError = ErrInvalidHexNonce
			return
		}
		cfg.Nonce = nonce
		cfg.NonceError = nil
	}
}

// WithBase64Nonce 将 Base64（StdEncoding）字符串解码为 GCM nonce 字节；
// 解码失败由 Encrypt/Decrypt 返回 ErrInvalidBase64Nonce。
// 语义与 WithNonce 相同，多个 nonce 选项按调用顺序后者覆盖前者。
func WithBase64Nonce(encoded string) Option {
	return func(cfg *Config) {
		nonce, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			cfg.NonceError = ErrInvalidBase64Nonce
			return
		}
		cfg.Nonce = nonce
		cfg.NonceError = nil
	}
}

// Encrypt 使用指定算法与模式加密明文。
//
// 输出为紧凑格式（无自描述，调用方必须持有 algorithm/mode 并在 Decrypt 对称传参）：
//   - GCM：nonce(12B) ‖ 密文 ‖ tag(16B)（nonce 随机前置）
//   - CBC/CFB/OFB：IV(块大小) ‖ 密文（IV 随机前置）
//   - CTR：counter(块大小) ‖ 密文（counter 随机前置）
//   - ECB：密文（无 IV、无前缀）
//
// 密钥必须通过一个密钥源选项提供（WithKey/WithKeyPassword/WithHexPassword/
// WithBase64Password）：多个选项按调用顺序覆盖，后调用的选项会覆盖先调用的选项。
// 缺源返回 ErrKeyRequired，长度按算法严格校验。IV/nonce 默认随机生成并前置；
// 也可通过 WithIV/WithNonce 外部提供（密文不含前缀，Decrypt 必须对称传入同一选项）。
//
// 无认证模式（ECB/CBC/CTR）密文可被任意篡改且解密无失败信号，仅限遗留兼容；
// 推荐使用 GCM（认证加密，篡改返回 ErrAuthenticationFailed）。
//
// 本函数为一次性便捷入口：内部构造 Encryptor（NewEncryptor）并立即调用
// Encrypt 后丢弃（使用即弃）；需要反复加解密同一密钥的调用方请复用 Encryptor。
func Encrypt(alg Algorithm, mode Mode, data []byte, opts ...Option) ([]byte, error) {
	e, err := NewEncryptor(alg, mode, opts...)
	if err != nil {
		return nil, err
	}
	return e.Encrypt(data)
}

// Decrypt 使用指定算法与模式解密密文，参数必须与 Encrypt 对称
// （同一 algorithm/mode、同一密钥源、同一 WithIV/WithNonce/WithAAD/WithPadding）。
// GCM 认证失败统一返回 ErrAuthenticationFailed；CBC/ECB 填充或对齐失败
// 返回 ErrInvalidPadding/对齐错误；CTR/CFB/OFB 无认证，不检测篡改。
//
// 本函数为一次性便捷入口：内部构造 Encryptor（NewEncryptor）并立即调用
// Decrypt 后丢弃；需要反复加解密同一密钥的调用方请复用 Encryptor。
func Decrypt(alg Algorithm, mode Mode, ciphertext []byte, opts ...Option) ([]byte, error) {
	e, err := NewEncryptor(alg, mode, opts...)
	if err != nil {
		return nil, err
	}
	return e.Decrypt(ciphertext)
}

// prepare 应用选项并完成入口校验（枚举范围、密钥解析、算法×模式兼容、
// 选项×模式兼容、IV/nonce 长度校验），返回已构造的 Cipher 与解析后的配置。
func prepare(alg Algorithm, mode Mode, opts []Option) (Cipher, *Config, error) {
	// 枚举范围校验最先执行：非法枚举值必须返回明确哨兵，
	// 避免后续依赖枚举值的方法（如 Algorithm.BlockSize 返回 0）产生非哨兵错误。
	if alg < AES128 || alg > TripleDES {
		return nil, nil, ErrUnknownAlgorithm
	}
	if mode < ECB || mode > GCM {
		return nil, nil, ErrUnknownMode
	}

	// 选项仅应用一次：密钥源计数、选项×模式校验均基于同一 cfg 消费，
	// 避免 WithHexPassword/WithBase64Password 被重复全量解码。
	cfg := ApplyOptions(opts)

	// 不安全算法/模式默认拒绝：DES/3DES 算法已被破解或安全性下降，
	// ECB 模式泄露明文模式。仅在显式 opt-in 后放行。
	if !cfg.AllowInsecure {
		if alg == DES || alg == TripleDES {
			return nil, nil, fmt.Errorf("%s: %w", alg.String(), ErrInsecureAlgorithm)
		}
		if mode == ECB {
			return nil, nil, fmt.Errorf("%s: %w", mode.String(), ErrInsecureAlgorithm)
		}
	}

	key, err := resolveKey(cfg)
	if err != nil {
		return nil, nil, err
	}

	// 算法×模式兼容：GCM 需要 16 字节块，DES/TripleDES（8 字节块）不支持。
	if mode == GCM && (alg == DES || alg == TripleDES) {
		return nil, nil, ErrIncompatibleAlgorithmMode
	}

	if err := validateModeOpts(mode, cfg); err != nil {
		return nil, nil, err
	}

	// 检查 IV/Nonce 解码错误
	if cfg.IVError != nil {
		return nil, nil, cfg.IVError
	}
	if cfg.NonceError != nil {
		return nil, nil, cfg.NonceError
	}

	if cfg.Nonce != nil && len(cfg.Nonce) != nonceSize {
		return nil, nil, ErrInvalidNonceLength
	}
	if cfg.IV != nil && len(cfg.IV) != alg.BlockSize() {
		return nil, nil, ErrInvalidIVLength
	}

	c, err := NewCipher(alg.String(), key)
	if err != nil {
		return nil, nil, err
	}

	return c, cfg, nil
}

// resolveKey 解析密钥源：检查解码错误和是否提供了密钥。
// 直接消费 prepare 单次应用后的 cfg，不进行互斥检查。
func resolveKey(cfg *Config) ([]byte, error) {
	// 检查 hex/base64 解码失败（KeyError）直接返回对应哨兵；
	// 其余情况返回密钥字节（WithKey/WithKeyPassword 的 KeyError 恒为 nil）。
	if cfg.KeyError != nil {
		return nil, cfg.KeyError
	}
	if len(cfg.Key) == 0 {
		return nil, ErrKeyRequired
	}
	return cfg.Key, nil
}

// validateModeOpts 校验选项与模式的兼容性（基于单次应用后的 cfg）：
// WithPadding 仅 ECB/CBC、WithAAD 与 WithNonce 仅 GCM、WithIV 不适用 ECB/GCM。
func validateModeOpts(mode Mode, cfg *Config) error {
	switch {
	case cfg.Padding != nil && mode != ECB && mode != CBC:
		return ErrPaddingNotSupported
	case cfg.AAD != nil && mode != GCM:
		return ErrAADNotSupported
	case cfg.Nonce != nil && mode != GCM:
		return ErrNonceNotSupported
	case cfg.IV != nil && (mode == ECB || mode == GCM):
		return ErrIVNotSupported
	}
	return nil
}
