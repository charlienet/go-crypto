package symmetric

import "github.com/charlienet/go-crypto/crypto"

// 类型别名：子包 API 直接复用根包契约类型，调用方无需显式 import 根包。
type (
	// Option 为模式构造/加密选项函数（与根包 crypto.Option 同型）。
	Option = crypto.Option
	// Config 为 Option 的应用目标（构造期使用，构造完成后不再读取）。
	Config = crypto.Config
	// Algorithm 对称加密算法枚举。
	Algorithm = crypto.Algorithm
	// Mode 分组加密工作模式枚举。
	Mode = crypto.Mode
	// Cipher 对称加密算法实例接口。
	Cipher = crypto.Cipher
	// CipherMode 模式对象接口（Encrypt/Decrypt 方法级并发安全）。
	CipherMode = crypto.CipherMode
	// StreamCipher 流式加密接口（非并发安全，持有流状态）。
	StreamCipher = crypto.StreamCipher
	// Padding 填充模式接口。
	Padding = crypto.Padding
)

// 选项构造器重导出：子包调用方无需同时 import 根包即可构造选项。
var (
	// WithKey 以原始密钥字节提供密钥（内部拷贝保存）。
	WithKey = crypto.WithKey
	// WithKeyPassword 将字符串直接作为密钥字节（无 KDF）。
	WithKeyPassword = crypto.WithKeyPassword
	// WithHexPassword 将 hex 字符串解码为密钥字节。
	WithHexPassword = crypto.WithHexPassword
	// WithBase64Password 将 Base64（StdEncoding）字符串解码为密钥字节。
	WithBase64Password = crypto.WithBase64Password
	// WithIV 外部提供 IV（或 CTR 计数器）：密文不含前缀。
	WithIV = crypto.WithIV
	// WithNonce 外部提供 GCM nonce：密文不含前缀，长度必须 12 字节。
	WithNonce = crypto.WithNonce
	// WithHexIV 将 hex 字符串解码为 IV 字节。
	WithHexIV = crypto.WithHexIV
	// WithBase64IV 将 Base64（StdEncoding）字符串解码为 IV 字节。
	WithBase64IV = crypto.WithBase64IV
	// WithHexNonce 将 hex 字符串解码为 GCM nonce 字节。
	WithHexNonce = crypto.WithHexNonce
	// WithBase64Nonce 将 Base64（StdEncoding）字符串解码为 GCM nonce 字节。
	WithBase64Nonce = crypto.WithBase64Nonce
	// WithAAD 设置 GCM 额外认证数据。
	WithAAD = crypto.WithAAD
	// WithPadding 设置填充模式。
	WithPadding = crypto.WithPadding
	// EmbedIV 启用 IV 前置（CBC/CFB/OFB）。
	EmbedIV = crypto.EmbedIV
	// EmbedNonce 启用 nonce 前置（GCM）。
	EmbedNonce = crypto.EmbedNonce
)
