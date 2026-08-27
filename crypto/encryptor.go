package crypto

import (
	"fmt"

	"github.com/charlienet/go-crypto/crypto/common"
)

// NewEncryptor 创建可复用对称加密对象。
//
// 构造流程与包级 Encrypt/Decrypt 完全同一管线（prepare）：枚举范围校验 →
// 选项应用（仅一次）→ 密钥源解析（多个选项按调用顺序覆盖）→ 算法×模式兼容（GCM 拒绝
// DES/TripleDES）→ 选项×模式校验 → IV/nonce 长度校验；随后经
// ModeExecutorFor 缓存对应模式的执行器（无状态），并冻结配置快照
// （IV/Nonce 再次拷贝，与外部传入切片彻底隔离；Key 为敏感密钥字节，
// 经 common.ZeroBytes 清零后置 nil，避免残留在对象内存中）。
//
// 构造完成后可反复调用 Encrypt/Decrypt。并发安全：构造后所有字段只读
// （底层 cipher.Block 并发安全、配置快照只读、执行器无状态），
// Encrypt/Decrypt 方法级并发安全，无需加锁。
func NewEncryptor(alg Algorithm, mode Mode, opts ...Option) (*Encryptor, error) {
	c, cfg, err := prepare(alg, mode, opts)
	if err != nil {
		return nil, err
	}

	ex, err := ModeExecutorFor(mode)
	if err != nil {
		return nil, fmt.Errorf("%w: mode %s (import crypto/symmetric)", err, mode)
	}

	// 冻结配置快照：IV/Nonce 拷贝（WithIV/WithNonce 已拷贝一次，此处再拷贝
	// 保证快照与一切外部切片彻底隔离）；AAD 在 WithAAD 内已拷贝，Padding
	// 为不可变接口引用，均可直接复用。
	frozen := &Config{
		EmbedIV:    cfg.EmbedIV,
		EmbedNonce: cfg.EmbedNonce,
		AAD:        cfg.AAD,
		Padding:    cfg.Padding,
		IV:         append([]byte(nil), cfg.IV...),
		Nonce:      append([]byte(nil), cfg.Nonce...),
	}

	// 密钥字节仅构造期使用（Cipher 已持有内部拷贝），及时清零擦除。
	common.ZeroBytes(cfg.Key)
	cfg.Key = nil
	cfg.KeyError = nil

	return &Encryptor{alg: alg, mode: mode, c: c, cfg: frozen, executor: ex}, nil
}

// Encryptor 可复用对称加密对象：构造一次绑定 算法+模式+密钥+选项，
// 之后可反复调用 Encrypt/Decrypt（方法级并发安全，无锁）。
//
// 每次 Encrypt/Decrypt 经缓存的执行器在内部新建低层 CipherMode 执行
// （GCM 用 NewGCM(nil, EmbedNonce(), ...)、CBC/CFB/OFB/CTR 用 WithRandom
// 变体或随机前缀逻辑），用完即弃；对象不持有任何可变状态。
type Encryptor struct {
	alg      Algorithm    // 构造时绑定的算法
	mode     Mode         // 构造时绑定的模式
	c        Cipher       // 只读；底层 cipher.Block 并发安全
	cfg      *Config      // 只读私有快照（IV/Nonce 已拷贝，Key 已清零置 nil）
	executor ModeExecutor // 无状态执行器，构造时经 ModeExecutorFor 缓存
}

// Encrypt 加密明文，输出紧凑格式密文（与包级 Encrypt 字节级一致）：
//   - GCM：nonce(12B) ‖ 密文 ‖ tag(16B)（nonce 随机前置）
//   - CBC/CFB/OFB/CTR：IV/counter(块大小) ‖ 密文（随机前置）
//   - ECB：密文（无 IV、无前缀）
//
// 每次调用内部新建低层模式对象并随即丢弃，不持有可变状态，可安全并发调用。
func (e *Encryptor) Encrypt(plaintext []byte) ([]byte, error) {
	return e.executor.Encrypt(e.c, e.alg, e.cfg, plaintext)
}

// Decrypt 解密密文，参数语义与构造时选项一致（GCM 认证失败返回
// ErrAuthenticationFailed，密文过短返回 ErrCiphertextTooShort，
// CBC/ECB 填充或对齐失败返回 ErrInvalidPadding/对齐错误）。
func (e *Encryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	return e.executor.Decrypt(e.c, e.alg, e.cfg, ciphertext)
}

// Algorithm 返回构造时绑定的算法。
func (e *Encryptor) Algorithm() Algorithm { return e.alg }

// Mode 返回构造时绑定的模式。
func (e *Encryptor) Mode() Mode { return e.mode }
