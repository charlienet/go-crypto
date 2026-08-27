package symmetric

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/charlienet/go-utils/bytesconv"
	"github.com/charlienet/go-crypto/crypto"
	"github.com/emmansun/gmsm/sm4"
)

// supported 对称算法表：算法键与根包注册表键一致（共 7 键，含 "AES" 别名键）。
// creator 记录底层块构造器与密钥/IV 长度元数据（CipherFactory.KeySize/IVSize 由此派生）。
var supported = map[string]*creator{
	"SM4":     {sm4.NewCipher, sm4.BlockSize, sm4.BlockSize},
	"AES":     {aes.NewCipher, aes.BlockSize, aes.BlockSize},
	"AES-128": {aes.NewCipher, aes.BlockSize, aes.BlockSize},
	"AES-192": {aes.NewCipher, 24, aes.BlockSize},
	"AES-256": {aes.NewCipher, 32, aes.BlockSize},
	"DES":     {des.NewCipher, des.BlockSize, des.BlockSize},
	"3DES":    {des.NewTripleDESCipher, 24, des.BlockSize},
}

// creator 底层块构造器与长度元数据。
type creator struct {
	new     func(key []byte) (cipher.Block, error)
	keySize int // 密钥长度（AES-128:16, AES-192:24, AES-256:32, SM4:16, DES:8, 3DES:24）
	ivSize  int
}

// newCipher 按算法名构造对称算法实例（CipherFactory.New 与本包 NewCipher 共用）。
//
// AES 系列按算法名严格校验密钥长度：
// AES-128/192/256 必须精确匹配（防止弱化降级，如 AES-256 配 16 字节密钥）；
// 泛名 "AES" 允许 16/24/32 三选一。
// SM4/DES/3DES 由各自实现自带长度校验，此处不改动。
func newCipher(name string, key []byte) (crypto.Cipher, error) {
	c, ok := supported[name]
	if !ok {
		return nil, fmt.Errorf("unsupported algorithm: %s", name)
	}

	switch name {
	case "AES":
		if len(key) != 16 && len(key) != 24 && len(key) != 32 {
			return nil, fmt.Errorf("%w: invalid key length %d for AES, want 16, 24 or 32", crypto.ErrInvalidKeyLength, len(key))
		}
	case "AES-128", "AES-192", "AES-256":
		if len(key) != c.keySize {
			return nil, fmt.Errorf("%w: invalid key length %d for %s, want %d", crypto.ErrInvalidKeyLength, len(key), name, c.keySize)
		}
	}

	block, err := c.new(key)
	if err != nil {
		return nil, err
	}

	return &symmetric{block: block, creator: c}, nil
}

// NewCipher 直接构造对称算法实例（不经注册表，行为与根包 NewCipher 一致；
// 根包 NewCipher 经注册表分发最终也落到同一构造路径）。
func NewCipher(name string, key []byte) (crypto.Cipher, error) {
	return newCipher(name, key)
}

// symmetric 对称算法实例实现。
type symmetric struct {
	block   cipher.Block
	creator *creator
}

func (a *symmetric) Block() cipher.Block {
	return a.block
}

// BlockSize 返回块大小（AES/SM4=16，DES/3DES=8），不是密钥长度。
func (a *symmetric) BlockSize() int {
	return a.block.BlockSize()
}

func (a *symmetric) IVSize() int {
	return a.creator.ivSize
}

// applyOpts 在构造期间应用选项，返回收集到的配置（nil Option 安全忽略）。
func (a *symmetric) applyOpts(opts []Option) *Config {
	return crypto.ApplyOptions(opts)
}

// --- StreamCipher ---

// streamCipher CTR 流加密实现。
//
// 非并发安全：内部持有 cipher.Stream 流状态，并发场景请各自构造独立实例。
type streamCipher struct {
	stream cipher.Stream
}

// Deprecated: 无认证，仅限遗留协议兼容。
//
// CTR 模式不提供任何完整性保护，密文可被任意篡改（bit-flipping），
// 必须与独立 MAC 组合使用，且组合顺序必须为 Encrypt-then-MAC。
// 仅适用于与 HMAC 等认证组合的遗留协议兼容场景。
//
// 替代方案：优先使用 GCM（认证加密，原生防篡改）；如确需流式 CTR，
// 必须自行叠加 MAC 并保持 Encrypt-then-MAC 顺序。
func (a *symmetric) NewCTR(iv []byte) (StreamCipher, error) {
	// 显式校验计数器长度：标准库 cipher.NewCTR 接受任意长度 IV，
	// 但长度非块大小时计数器语义不符合预期，且这是公开 API 不允许 panic 的边界。
	if len(iv) != a.BlockSize() {
		return nil, errors.New("iv length is not equal to block size")
	}
	return &streamCipher{stream: cipher.NewCTR(a.block, iv)}, nil
}

func (s *streamCipher) XORKeyStream(src []byte) []byte {
	dst := make([]byte, len(src))
	s.stream.XORKeyStream(dst, src)
	return dst
}

func (s *streamCipher) Stream(reader io.Reader) io.Reader {
	return cipher.StreamReader{S: s.stream, R: reader}
}

// --- GCM ---

// NewGCM 创建 GCM 模式对象，使用固定 nonce。
// 警告：固定 nonce 下同一 mode 对象仅允许 Encrypt 一次——GCM 复用相同
// nonce 加密多条消息会直接泄露明文异或（keystream 消去），机密性完全丧失。
// 每条消息应使用新 nonce：传入 nil 并启用 EmbedNonce，或使用
// NewGCMWithRandomNonce（每次 Encrypt 随机生成 nonce）。
//
// 特别注意：固定 nonce 与 EmbedNonce 同时使用时，每次 Encrypt 都会把同一
// nonce 嵌入密文前缀——同一对象加密两条消息即构成 nonce 重用，属危险用法，
// 仅用于固定格式兼容，禁止用于新协议。
func (a *symmetric) NewGCM(nonce []byte, opts ...Option) (CipherMode, error) {
	gcm, err := cipher.NewGCM(a.block)
	if err != nil {
		return nil, err
	}

	cfg := a.applyOpts(opts)

	// nonce 长度校验无条件执行（无论是否启用 EmbedNonce）：
	// - 过长 nonce 在 Encrypt 中被静默截断、过短被补零，导致 nonce 碰撞；
	// - nil nonce 在 Decrypt 中直接传给 gcm.Open，触发标准库 panic。
	// 仅 EmbedNonce 下 nil nonce 合法（Encrypt 随机生成并嵌入），保持既有行为。
	if len(nonce) == 0 {
		if !cfg.EmbedNonce {
			return nil, errors.New("nonce is required when EmbedNonce is not enabled")
		}
	} else if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("invalid nonce length %d, want %d", len(nonce), gcm.NonceSize())
	}

	// 拷贝保存 nonce（与 block_aead.go baseNonce 的处理一致），
	// 防止调用方后续修改原切片影响已构造的 GCM 对象。
	// nil nonce 拷贝后仍为 nil，EmbedNonce 随机生成路径行为不变。
	nonceCopy := append([]byte(nil), nonce...)

	return &algo_gcm{
		block:      a.block,
		gcm:        gcm,
		nonce:      nonceCopy,
		embednonce: cfg.EmbedNonce,
		// Config 不承载 randomNonce（无对应 Option），固定 nonce 路径恒为 false，
		// 行为与旧 modeConfig 一致。
		randomNonce: false,
		aad:         cfg.AAD,
	}, nil
}

func (a *symmetric) NewGCMWithRandomNonce() (CipherMode, error) {
	gcm, err := cipher.NewGCM(a.block)
	if err != nil {
		return nil, err
	}

	return &algo_gcm{
		block:       a.block,
		gcm:         gcm,
		embednonce:  true,
		randomNonce: true,
	}, nil
}

type algo_gcm struct {
	block       cipher.Block
	gcm         cipher.AEAD
	nonce       []byte
	embednonce  bool
	randomNonce bool
	aad         []byte
}

func (a *algo_gcm) NonceSize() int {
	return a.gcm.NonceSize()
}

func (a *algo_gcm) Encrypt(plainText []byte) (bytesconv.BytesResult, error) {
	nonce := make([]byte, a.gcm.NonceSize())
	if a.randomNonce || len(a.nonce) == 0 {
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return nil, err
		}
	} else {
		copy(nonce, a.nonce)
	}

	if a.embednonce {
		return a.gcm.Seal(nonce, nonce, plainText, a.aad), nil
	}
	return a.gcm.Seal(nil, nonce, plainText, a.aad), nil
}

func (a *algo_gcm) Decrypt(ciphertext []byte) (bytesconv.BytesResult, error) {
	if a.embednonce {
		ns := a.gcm.NonceSize()
		if len(ciphertext) < ns {
			return nil, crypto.ErrCiphertextTooShort
		}
		nonce, cipherText := ciphertext[:ns], ciphertext[ns:]
		return a.gcm.Open(nil, nonce, cipherText, a.aad)
	}
	return a.gcm.Open(nil, a.nonce, ciphertext, a.aad)
}

// --- CBC ---

// newCBC 构造 CBC 模式对象，NewCBC 与 NewCBCWithRandomIV 共用核心逻辑。
func (a *symmetric) newCBC(iv []byte, cfg *Config) (*algo_cbc, error) {
	if len(iv) != a.BlockSize() {
		return nil, errors.New("iv length is not equal to block size")
	}

	if cfg.AAD != nil {
		return nil, errors.New("WithAAD 仅支持 GCM")
	}

	padding := cfg.Padding
	if padding == nil {
		padding = crypto.PKCS7{}
	}

	return &algo_cbc{
		block:   a.block,
		creator: a.creator,
		iv:      append([]byte(nil), iv...), // 拷贝保存，防止调用方后续修改原切片影响已构造的对象
		embediv: cfg.EmbedIV,
		padding: padding,
	}, nil
}

// NewCBC 创建 CBC 模式对象，使用固定 iv。
// 警告：固定 IV 下同一 mode 对象仅允许 Encrypt 一次——每次 Encrypt 都从相同
// IV 重新初始化，重复 Encrypt 复用完全相同 keystream（C1⊕C2 = P1⊕P2 直接泄露
// 明文）。每条消息应使用新 IV，推荐使用 NewCBCWithRandomIV。
func (a *symmetric) NewCBC(iv []byte, opts ...Option) (CipherMode, error) {
	return a.newCBC(iv, a.applyOpts(opts))
}

// NewCBCWithRandomIV 创建 CBC 模式对象：每次 Encrypt 从 crypto/rand 生成全新
// 随机 IV 并嵌入密文前缀（EmbedIV 语义），Decrypt 自动从密文提取 IV。
// 调用方无需（也不应）传入固定 IV，同一对象可安全重复 Encrypt。
func (a *symmetric) NewCBCWithRandomIV(opts ...Option) (CipherMode, error) {
	cfg := a.applyOpts(opts)
	cfg.EmbedIV = true
	// 占位 IV 仅用于通过长度校验，实际 IV 在每次 Encrypt 时随机生成。
	c, err := a.newCBC(make([]byte, a.BlockSize()), cfg)
	if err != nil {
		return nil, err
	}
	c.randomIV = true
	return c, nil
}

type algo_cbc struct {
	block    cipher.Block
	creator  *creator
	iv       []byte
	embediv  bool
	randomIV bool
	padding  Padding
}

func (a *algo_cbc) Encrypt(plainText []byte) (bytesconv.BytesResult, error) {
	paddedText, err := a.padding.Padding(a.block.BlockSize(), plainText)
	if err != nil {
		return nil, err
	}

	iv := a.iv
	if a.randomIV {
		iv = make([]byte, a.block.BlockSize())
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return nil, err
		}
	}

	stream := cipher.NewCBCEncrypter(a.block, iv)

	if a.embediv {
		bs := a.block.BlockSize()
		cipherText := make([]byte, len(paddedText)+bs)
		copy(cipherText, iv)
		stream.CryptBlocks(cipherText[bs:], paddedText)
		return cipherText, nil
	}

	cipherText := make([]byte, len(paddedText))
	stream.CryptBlocks(cipherText, paddedText)
	return cipherText, nil
}

func (a *algo_cbc) Decrypt(ciphertext []byte) (bytesconv.BytesResult, error) {
	if a.embediv {
		bs := a.block.BlockSize()
		if len(ciphertext) < bs {
			return nil, crypto.ErrCiphertextTooShort
		}
		// 显式校验对齐，避免 CryptBlocks 对非整块密文触发标准库 panic（远程 DoS）
		if (len(ciphertext)-bs)%bs != 0 {
			return nil, crypto.ErrCiphertextNotAligned
		}
		// 拷贝后再解密：CryptBlocks 以输入为输出缓冲区（原地解密），
		// 直接操作调用方切片会意外修改其输入。函数不应修改输入（Go 惯例）。
		// 返回值与输入无共享底层（基于独立拷贝 buf 的截断视图）。
		buf := append([]byte(nil), ciphertext...)
		iv, cipherText := buf[:bs], buf[bs:]
		stream := cipher.NewCBCDecrypter(a.block, iv)
		stream.CryptBlocks(cipherText, cipherText)
		return a.padding.UnPadding(a.block.BlockSize(), cipherText)
	}

	// 显式校验对齐，避免 CryptBlocks 对非整块密文触发标准库 panic（远程 DoS）
	if len(ciphertext)%a.block.BlockSize() != 0 {
		return nil, crypto.ErrCiphertextNotAligned
	}

	stream := cipher.NewCBCDecrypter(a.block, a.iv)
	dst := make([]byte, len(ciphertext))
	stream.CryptBlocks(dst, ciphertext)
	return a.padding.UnPadding(a.block.BlockSize(), dst)
}

// --- ECB ---

// Deprecated: 不安全，仅限遗留数据兼容。
//
// ECB 模式下相同明文块产生相同密文块，直接泄露数据模式与重复信息，
// 不应视为安全加密。仅适用于遗留数据兼容或非安全格式转换
// （如某些行业存量格式），禁止用于新系统加密。
//
// 替代方案：优先使用 GCM AEAD（NewGCMWithRandomNonce）；如需分块流式
// 加密，请使用 crypto/envelope 子包的 fsb1 流式 API。
func (a *symmetric) NewECB(opts ...Option) (CipherMode, error) {
	cfg := a.applyOpts(opts)

	if cfg.AAD != nil {
		return nil, errors.New("WithAAD 仅支持 GCM")
	}

	padding := cfg.Padding
	if padding == nil {
		padding = crypto.PKCS7{}
	}

	return &algo_ecb{
		block:   a.block,
		creator: a.creator,
		padding: padding,
	}, nil
}

// --- CFB ---

// newCFB 构造 CFB 模式对象，NewCFB 与 NewCFBWithRandomIV 共用核心逻辑。
func (a *symmetric) newCFB(iv []byte, cfg *Config) (*algo_cfb, error) {
	if len(iv) != a.BlockSize() {
		return nil, errors.New("iv length is not equal to block size")
	}

	if cfg.AAD != nil {
		return nil, errors.New("WithAAD 仅支持 GCM")
	}

	return &algo_cfb{
		block:   a.block,
		iv:      append([]byte(nil), iv...), // 拷贝保存，防止调用方后续修改原切片影响已构造的对象
		embediv: cfg.EmbedIV,
	}, nil
}

// NewCFB 创建 CFB 模式对象，使用固定 iv。
// 警告：固定 IV 下同一 mode 对象仅允许 Encrypt 一次——每次 Encrypt 都从相同
// IV 重新初始化，重复 Encrypt 复用完全相同 keystream（C1⊕C2 = P1⊕P2 直接泄露
// 明文）。每条消息应使用新 IV，推荐使用 NewCFBWithRandomIV。
func (a *symmetric) NewCFB(iv []byte, opts ...Option) (CipherMode, error) {
	return a.newCFB(iv, a.applyOpts(opts))
}

// NewCFBWithRandomIV 创建 CFB 模式对象：每次 Encrypt 从 crypto/rand 生成全新
// 随机 IV 并嵌入密文前缀（EmbedIV 语义），Decrypt 自动从密文提取 IV。
// 调用方无需（也不应）传入固定 IV，同一对象可安全重复 Encrypt。
func (a *symmetric) NewCFBWithRandomIV(opts ...Option) (CipherMode, error) {
	cfg := a.applyOpts(opts)
	cfg.EmbedIV = true
	// 占位 IV 仅用于通过长度校验，实际 IV 在每次 Encrypt 时随机生成。
	c, err := a.newCFB(make([]byte, a.BlockSize()), cfg)
	if err != nil {
		return nil, err
	}
	c.randomIV = true
	return c, nil
}

type algo_cfb struct {
	block    cipher.Block
	iv       []byte
	embediv  bool
	randomIV bool
}

func (a *algo_cfb) Encrypt(plainText []byte) (bytesconv.BytesResult, error) {
	iv := a.iv
	if a.randomIV {
		iv = make([]byte, a.block.BlockSize())
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return nil, err
		}
	}

	stream := cipher.NewCFBEncrypter(a.block, iv)

	if a.embediv {
		bs := a.block.BlockSize()
		cipherText := make([]byte, len(plainText)+bs)
		copy(cipherText, iv)
		stream.XORKeyStream(cipherText[bs:], plainText)
		return cipherText, nil
	}

	cipherText := make([]byte, len(plainText))
	stream.XORKeyStream(cipherText, plainText)
	return cipherText, nil
}

func (a *algo_cfb) Decrypt(cipherText []byte) (bytesconv.BytesResult, error) {
	if a.embediv {
		bs := a.block.BlockSize()
		if len(cipherText) < bs {
			return nil, crypto.ErrCiphertextTooShort
		}
		iv, ct := cipherText[:bs], cipherText[bs:]
		stream := cipher.NewCFBDecrypter(a.block, iv)
		plainText := make([]byte, len(ct))
		stream.XORKeyStream(plainText, ct)
		return plainText, nil
	}

	stream := cipher.NewCFBDecrypter(a.block, a.iv)
	plainText := make([]byte, len(cipherText))
	stream.XORKeyStream(plainText, cipherText)
	return plainText, nil
}

// --- OFB ---

// newOFB 构造 OFB 模式对象，NewOFB 与 NewOFBWithRandomIV 共用核心逻辑。
func (a *symmetric) newOFB(iv []byte, cfg *Config) (*algo_ofb, error) {
	if len(iv) != a.BlockSize() {
		return nil, errors.New("iv length is not equal to block size")
	}

	if cfg.AAD != nil {
		return nil, errors.New("WithAAD 仅支持 GCM")
	}

	return &algo_ofb{
		block:   a.block,
		iv:      append([]byte(nil), iv...), // 拷贝保存，防止调用方后续修改原切片影响已构造的对象
		embediv: cfg.EmbedIV,
	}, nil
}

// NewOFB 创建 OFB 模式对象，使用固定 iv。
// 警告：固定 IV 下同一 mode 对象仅允许 Encrypt 一次——每次 Encrypt 都从相同
// IV 重新初始化，重复 Encrypt 复用完全相同 keystream（C1⊕C2 = P1⊕P2 直接泄露
// 明文）。每条消息应使用新 IV，推荐使用 NewOFBWithRandomIV。
func (a *symmetric) NewOFB(iv []byte, opts ...Option) (CipherMode, error) {
	return a.newOFB(iv, a.applyOpts(opts))
}

// NewOFBWithRandomIV 创建 OFB 模式对象：每次 Encrypt 从 crypto/rand 生成全新
// 随机 IV 并嵌入密文前缀（EmbedIV 语义），Decrypt 自动从密文提取 IV。
// 调用方无需（也不应）传入固定 IV，同一对象可安全重复 Encrypt。
func (a *symmetric) NewOFBWithRandomIV(opts ...Option) (CipherMode, error) {
	cfg := a.applyOpts(opts)
	cfg.EmbedIV = true
	// 占位 IV 仅用于通过长度校验，实际 IV 在每次 Encrypt 时随机生成。
	c, err := a.newOFB(make([]byte, a.BlockSize()), cfg)
	if err != nil {
		return nil, err
	}
	c.randomIV = true
	return c, nil
}

type algo_ofb struct {
	block    cipher.Block
	iv       []byte
	embediv  bool
	randomIV bool
}

func (a *algo_ofb) Encrypt(plainText []byte) (bytesconv.BytesResult, error) {
	iv := a.iv
	if a.randomIV {
		iv = make([]byte, a.block.BlockSize())
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return nil, err
		}
	}

	stream := cipher.NewOFB(a.block, iv)

	if a.embediv {
		bs := a.block.BlockSize()
		cipherText := make([]byte, len(plainText)+bs)
		copy(cipherText, iv)
		stream.XORKeyStream(cipherText[bs:], plainText)
		return cipherText, nil
	}

	cipherText := make([]byte, len(plainText))
	stream.XORKeyStream(cipherText, plainText)
	return cipherText, nil
}

func (a *algo_ofb) Decrypt(cipherText []byte) (bytesconv.BytesResult, error) {
	if a.embediv {
		bs := a.block.BlockSize()
		if len(cipherText) < bs {
			return nil, crypto.ErrCiphertextTooShort
		}
		iv, ct := cipherText[:bs], cipherText[bs:]
		stream := cipher.NewOFB(a.block, iv)
		plainText := make([]byte, len(ct))
		stream.XORKeyStream(plainText, ct)
		return plainText, nil
	}

	stream := cipher.NewOFB(a.block, a.iv)
	plainText := make([]byte, len(cipherText))
	stream.XORKeyStream(plainText, cipherText)
	return plainText, nil
}

type algo_ecb struct {
	block   cipher.Block
	creator *creator
	padding Padding
}

func (a *algo_ecb) Encrypt(plainText []byte) (bytesconv.BytesResult, error) {
	paddedText, err := a.padding.Padding(a.block.BlockSize(), plainText)
	if err != nil {
		return nil, err
	}

	dst := make([]byte, len(paddedText))
	bs := a.block.BlockSize()
	for i := 0; i < len(paddedText); i += bs {
		a.block.Encrypt(dst[i:i+bs], paddedText[i:i+bs])
	}
	return dst, nil
}

func (a *algo_ecb) Decrypt(cipherText []byte) (bytesconv.BytesResult, error) {
	bs := a.block.BlockSize()
	// 显式校验对齐，避免切片越界 panic（远程 DoS）。
	// ECB Encrypt 无需同类防护：其输入均先经 padding.Padding，
	// 输出必为块大小整数倍（NoPadding 非对齐时在 Padding 阶段即返回 error）。
	if len(cipherText)%bs != 0 {
		return nil, crypto.ErrCiphertextNotAligned
	}
	dst := make([]byte, len(cipherText))
	for i := 0; i < len(cipherText); i += bs {
		a.block.Decrypt(dst[i:i+bs], cipherText[i:i+bs])
	}
	return a.padding.UnPadding(a.block.BlockSize(), dst)
}
