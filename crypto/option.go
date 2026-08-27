package crypto

// Config 是 Option 的应用目标。构造期使用：Option 仅在构造期被应用一次，
// 构造完成后 Config 不再被读取，调用方不得跨构造复用同一份选项。
//
// 字段分三层，对应不同 API 层的消费方：
//
//	低层（NewGCM/NewCBC/NewECB/NewCFB/NewOFB 及各 WithRandom* 变体）：
//	    读取 EmbedIV/EmbedNonce/AAD/Padding，忽略其余字段；
//	模式化（Encrypt/Decrypt 协议入口）：额外读取 IV/Nonce/Key*；
//	密钥源字段由 With* 选项写入、resolveKey 消费。
type Config struct {
	// ---- 低层通用选项 ----
	EmbedIV    bool    // EmbedIV()：CBC/CFB/OFB 密文前置 IV
	EmbedNonce bool    // EmbedNonce()：GCM 密文前置 nonce
	AAD        []byte  // WithAAD()：GCM 附加认证数据（构造器内拷贝）
	Padding    Padding // WithPadding()：ECB/CBC 填充；nil 时缺省 PKCS7

	// ---- 模式化 API 选项（Encrypt/Decrypt 专用）----
	IV    []byte // WithIV()：外部 IV/计数器；nil 表示随机生成并前置
	Nonce []byte // WithNonce()：外部 GCM nonce；nil 表示随机生成并前置
	IVError   error  // hex/base64 IV 解码失败
	NonceError error // hex/base64 nonce 解码失败

	// ---- 密钥源（多个选项按调用顺序覆盖）----
	Key      []byte // 解析出的密钥字节（多个 With* 选项按调用顺序覆盖）
	KeyError error  // hex/base64 解码失败错误（ErrInvalidHexPassword/ErrInvalidBase64Password）；nil 表示未失败

	// ---- 安全策略 ----
	AllowInsecure bool // WithInsecureAlgorithms()：允许使用不安全算法（DES/3DES）和模式（ECB）
}

// Option 是模式构造/加密选项函数，通过 WithAAD/WithPadding/EmbedNonce/EmbedIV
// 及 WithKey/WithKeyPassword/WithHexPassword/WithBase64Password/WithIV/WithNonce
// 等构造器生成，可传入 NewGCM/NewCBC/NewECB/NewCFB/NewOFB 及各 WithRandom* 变体、
// Encrypt/Decrypt 协议入口，也用于 EnvelopeCodec 适配器的 Encrypt/Decrypt 转发层。
//
// 签名引用导出类型 Config：任何包均可定义 func(*Config) 并转换为本类型，
// 子包无需根包帮助即可实现自定义 Option。
type Option func(*Config)

// ApplyOptions 依次应用选项并返回收集到的配置。
// nil Option 会被安全忽略；选项仅应用一次，调用方不得复用返回值
// 再次传入构造器（重复应用会破坏密钥源互斥计数等语义）。
func ApplyOptions(opts []Option) *Config {
	cfg := &Config{}
	for _, opt := range opts {
		if opt != nil {
			opt(cfg)
		}
	}
	return cfg
}

// AADFromOptions 从选项列表中提取 GCM AAD；未设置时返回 nil。
// 供外部包（如 envelope 适配器）透传 Option 后提取 AAD 使用。
// nil Option 会被安全忽略。
func AADFromOptions(opts ...Option) []byte {
	return ApplyOptions(opts).AAD
}

// EmbedIV 启用 IV 前置：CBC/CFB/OFB 模式下，Encrypt 输出密文前置
// 本次使用的随机 IV，Decrypt 自动从密文头部提取。
func EmbedIV() Option {
	return func(cfg *Config) {
		cfg.EmbedIV = true
	}
}

// EmbedNonce 启用 nonce 前置：GCM 模式下，Encrypt 输出密文前置
// 本次使用的随机 nonce，Decrypt 自动从密文头部提取。
func EmbedNonce() Option {
	return func(cfg *Config) {
		cfg.EmbedNonce = true
	}
}

// WithAAD 设置 GCM 额外认证数据。
func WithAAD(aad []byte) Option {
	return func(cfg *Config) {
		// 拷贝保存，防止调用方后续修改原切片影响已构造的 mode 对象
		cfg.AAD = append([]byte(nil), aad...)
	}
}

// WithPadding 设置填充模式
func WithPadding(padding Padding) Option {
	return func(cfg *Config) {
		cfg.Padding = padding
	}
}

// WithInsecureAlgorithms 允许使用不安全的算法和模式。
//
// 默认情况下，以下算法和模式被拒绝（返回 ErrInsecureAlgorithm）：
//   - 算法：DES（已被破解）、TripleDES（安全性下降）
//   - 模式：ECB（泄露明文模式）
//
// 仅在对接遗留系统时必须使用。新代码应使用 AES + GCM。
func WithInsecureAlgorithms() Option {
	return func(cfg *Config) {
		cfg.AllowInsecure = true
	}
}
