package symmetric

import (
	"crypto/cipher"
	"crypto/rand"
	"io"

	"github.com/charlienet/go-crypto"
)

// nonceSize 标准 GCM nonce 长度（与根包协议层校验一致，固定 12 字节）。
const nonceSize = 12

// modeExecutors 六种工作模式执行器表，register.go 的 init() 逐项注册。
// 各执行器无状态：每次 Encrypt/Decrypt 内部新建低层模式对象并随即丢弃，
// 跨消息复用固定 IV/nonce 的模式对象会复用 keystream，直接泄露明文。
var modeExecutors = map[crypto.Mode]crypto.ModeExecutor{
	crypto.GCM: gcmExecutor{},
	crypto.CBC: cbcExecutor{},
	crypto.ECB: ecbExecutor{},
	crypto.CFB: cfbExecutor{},
	crypto.OFB: ofbExecutor{},
	crypto.CTR: ctrExecutor{},
}

// gcmExecutor GCM 认证加密执行器。
// 输出格式（与根包 Encrypt 紧凑格式字节级一致）：
//   - 默认（无 WithNonce）：nonce(12B) ‖ 密文 ‖ tag(16B)
//   - 显式 nonce（WithNonce）：密文 ‖ tag（无前缀，解密须对称传同一 nonce）
type gcmExecutor struct{}

func (gcmExecutor) Encrypt(c crypto.Cipher, alg crypto.Algorithm, cfg *crypto.Config, plaintext []byte) ([]byte, error) {
	m, err := newGCM(c, cfg)
	if err != nil {
		return nil, err
	}
	out, err := m.Encrypt(plaintext)
	if err != nil {
		return nil, err
	}
	return []byte(out), nil
}

func (gcmExecutor) Decrypt(c crypto.Cipher, alg crypto.Algorithm, cfg *crypto.Config, ciphertext []byte) ([]byte, error) {
	// 密文长度 < nonce 大小必然无法容纳嵌入 nonce（默认路径），
	// 与认证失败区分，避免诊断信息被统一哨兵吞没。
	if len(ciphertext) < nonceSize {
		return nil, crypto.ErrCiphertextTooShort
	}
	m, err := newGCM(c, cfg)
	if err != nil {
		return nil, err
	}
	out, err := m.Decrypt(ciphertext)
	if err != nil {
		return nil, crypto.ErrAuthenticationFailed
	}
	return []byte(out), nil
}

// newGCM 构造 GCM 模式对象：显式 nonce 走固定 nonce 路径（无前缀）；
// 默认走 EmbedNonce 路径（Encrypt 随机生成 nonce 并前置）。
func newGCM(c crypto.Cipher, cfg *crypto.Config) (crypto.CipherMode, error) {
	var aadOpts []crypto.Option
	if cfg.AAD != nil {
		aadOpts = append(aadOpts, crypto.WithAAD(cfg.AAD))
	}
	if cfg.Nonce != nil {
		return c.NewGCM(cfg.Nonce, aadOpts...)
	}
	return c.NewGCM(nil, append(aadOpts, crypto.EmbedNonce())...)
}

// cbcExecutor CBC 加密执行器。
// 输出格式：默认（无 WithIV）IV(块大小) ‖ 密文（IV 随机前置）；
// 显式 IV（WithIV）时密文无前缀。填充缺省 PKCS7。
type cbcExecutor struct{}

func (cbcExecutor) Encrypt(c crypto.Cipher, alg crypto.Algorithm, cfg *crypto.Config, plaintext []byte) ([]byte, error) {
	m, err := newCBC(c, cfg)
	if err != nil {
		return nil, err
	}
	out, err := m.Encrypt(plaintext)
	if err != nil {
		return nil, err
	}
	return []byte(out), nil
}

func (cbcExecutor) Decrypt(c crypto.Cipher, alg crypto.Algorithm, cfg *crypto.Config, ciphertext []byte) ([]byte, error) {
	m, err := newCBC(c, cfg)
	if err != nil {
		return nil, err
	}
	out, err := m.Decrypt(ciphertext)
	if err != nil {
		return nil, err
	}
	return []byte(out), nil
}

// newCBC 构造 CBC 模式对象：显式 IV 走固定 IV 路径（无前缀）；
// 默认走 NewCBCWithRandomIV（每次 Encrypt 随机 IV 并前置）。
func newCBC(c crypto.Cipher, cfg *crypto.Config) (crypto.CipherMode, error) {
	padOpts := paddingOpts(cfg)
	if cfg.IV != nil {
		return c.NewCBC(cfg.IV, padOpts...)
	}
	return c.NewCBCWithRandomIV(padOpts...)
}

// ecbExecutor ECB 加密执行器（不安全，仅遗留兼容）。
// 输出格式：无 IV、无前缀；填充缺省 PKCS7。
// 构造时透传协议层 AllowInsecure 策略（modeOpts）：协议层 prepare 已
// 校验闸门（WithInsecureAlgorithms 放行），此处放行低层 NewECB。
type ecbExecutor struct{}

func (ecbExecutor) Encrypt(c crypto.Cipher, alg crypto.Algorithm, cfg *crypto.Config, plaintext []byte) ([]byte, error) {
	m, err := c.NewECB(modeOpts(cfg)...)
	if err != nil {
		return nil, err
	}
	out, err := m.Encrypt(plaintext)
	if err != nil {
		return nil, err
	}
	return []byte(out), nil
}

func (ecbExecutor) Decrypt(c crypto.Cipher, alg crypto.Algorithm, cfg *crypto.Config, ciphertext []byte) ([]byte, error) {
	m, err := c.NewECB(modeOpts(cfg)...)
	if err != nil {
		return nil, err
	}
	out, err := m.Decrypt(ciphertext)
	if err != nil {
		return nil, err
	}
	return []byte(out), nil
}

// cfbExecutor CFB 加密执行器。
// 输出格式：默认（无 WithIV）IV(块大小) ‖ 密文（IV 随机前置）；
// 显式 IV（WithIV）时密文无前缀。无认证、无填充。
type cfbExecutor struct{}

func (cfbExecutor) Encrypt(c crypto.Cipher, alg crypto.Algorithm, cfg *crypto.Config, plaintext []byte) ([]byte, error) {
	m, err := newCFB(c, cfg)
	if err != nil {
		return nil, err
	}
	out, err := m.Encrypt(plaintext)
	if err != nil {
		return nil, err
	}
	return []byte(out), nil
}

func (cfbExecutor) Decrypt(c crypto.Cipher, alg crypto.Algorithm, cfg *crypto.Config, ciphertext []byte) ([]byte, error) {
	m, err := newCFB(c, cfg)
	if err != nil {
		return nil, err
	}
	out, err := m.Decrypt(ciphertext)
	if err != nil {
		return nil, err
	}
	return []byte(out), nil
}

// newCFB 构造 CFB 模式对象：显式 IV 走固定 IV 路径；默认随机 IV 前置。
func newCFB(c crypto.Cipher, cfg *crypto.Config) (crypto.CipherMode, error) {
	if cfg.IV != nil {
		return c.NewCFB(cfg.IV)
	}
	return c.NewCFBWithRandomIV()
}

// ofbExecutor OFB 加密执行器。
// 输出格式：默认（无 WithIV）IV(块大小) ‖ 密文（IV 随机前置）；
// 显式 IV（WithIV）时密文无前缀。无认证、无填充。
type ofbExecutor struct{}

func (ofbExecutor) Encrypt(c crypto.Cipher, alg crypto.Algorithm, cfg *crypto.Config, plaintext []byte) ([]byte, error) {
	m, err := newOFB(c, cfg)
	if err != nil {
		return nil, err
	}
	out, err := m.Encrypt(plaintext)
	if err != nil {
		return nil, err
	}
	return []byte(out), nil
}

func (ofbExecutor) Decrypt(c crypto.Cipher, alg crypto.Algorithm, cfg *crypto.Config, ciphertext []byte) ([]byte, error) {
	m, err := newOFB(c, cfg)
	if err != nil {
		return nil, err
	}
	out, err := m.Decrypt(ciphertext)
	if err != nil {
		return nil, err
	}
	return []byte(out), nil
}

// newOFB 构造 OFB 模式对象：显式 IV 走固定 IV 路径；默认随机 IV 前置。
func newOFB(c crypto.Cipher, cfg *crypto.Config) (crypto.CipherMode, error) {
	if cfg.IV != nil {
		return c.NewOFB(cfg.IV)
	}
	return c.NewOFBWithRandomIV()
}

// ctrExecutor CTR 流加密执行器。
// 输出格式：默认（无 WithIV）counter(块大小) ‖ 密文（counter 随机前置）；
// 显式计数器（WithIV）时密文无前缀。无认证，仅限遗留协议兼容。
type ctrExecutor struct{}

func (ctrExecutor) Encrypt(c crypto.Cipher, alg crypto.Algorithm, cfg *crypto.Config, plaintext []byte) ([]byte, error) {
	counter := cfg.IV
	embed := false
	if counter == nil {
		counter = make([]byte, alg.BlockSize())
		if _, err := io.ReadFull(rand.Reader, counter); err != nil {
			return nil, err
		}
		embed = true
	}

	// 计数器长度入口已校验（WithIV 长度 / 内部按块大小生成），此处不会失败，
	// 防御性保留错误传播（公开 API 不 panic）。
	if _, err := c.NewCTR(counter); err != nil {
		return nil, err
	}

	// 用标准库流直写目标缓冲区（counter ‖ 密文），一次分配避免二次拷贝。
	stream := cipher.NewCTR(c.Block(), counter)
	if !embed {
		out := make([]byte, len(plaintext))
		stream.XORKeyStream(out, plaintext)
		return out, nil
	}

	bs := alg.BlockSize()
	out := make([]byte, bs+len(plaintext))
	copy(out, counter)
	stream.XORKeyStream(out[bs:], plaintext)
	return out, nil
}

func (ctrExecutor) Decrypt(c crypto.Cipher, alg crypto.Algorithm, cfg *crypto.Config, ciphertext []byte) ([]byte, error) {
	counter := cfg.IV
	ct := ciphertext
	if counter == nil {
		bs := alg.BlockSize()
		if len(ciphertext) < bs {
			return nil, crypto.ErrCiphertextTooShort
		}
		counter, ct = ciphertext[:bs], ciphertext[bs:]
	}

	// 计数器长度已保证（WithIV 入口校验 / 密文前缀提取），防御性保留错误传播。
	if _, err := c.NewCTR(counter); err != nil {
		return nil, err
	}

	out := make([]byte, len(ct))
	cipher.NewCTR(c.Block(), counter).XORKeyStream(out, ct)
	return out, nil
}

// paddingOpts 仅在显式设置填充时透传 WithPadding；缺省由低层默认 PKCS7。
func paddingOpts(cfg *crypto.Config) []crypto.Option {
	if cfg.Padding != nil {
		return []crypto.Option{crypto.WithPadding(cfg.Padding)}
	}
	return nil
}

// modeOpts 构造 ECB 等需策略透传模式的低层选项：透传显式填充，并把
// 协议层已校验的 AllowInsecure 策略透传给低层闸门（协议层放行后，
// 低层 NewECB 不再二次拒绝；未放行时协议层在 prepare 已拒绝，不会到达）。
func modeOpts(cfg *crypto.Config) []crypto.Option {
	opts := paddingOpts(cfg)
	if cfg.AllowInsecure {
		opts = append(opts, crypto.WithInsecureAlgorithms())
	}
	return opts
}
