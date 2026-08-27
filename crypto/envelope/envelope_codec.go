package envelope

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"sync"

	rootcrypto "github.com/charlienet/go-crypto/crypto"
)

// EnvelopeCodec 信封适配器接口：将高层信封格式（如 gcx1）抽象为可注册的
// 编解码器，允许应用侧通过 RegisterEnvelopeCodec 接入自定义"格式翻译"
// 底层实现，同时保持 Encrypt/Decrypt 入口签名不变。
//
// 实现要求：
//   - 无状态、并发安全：同一 codec 实例可被任意 goroutine 并发调用
//     Encrypt/Decrypt，实现内部不得持有可变状态（密钥、nonce 等一律入参）。
//   - 底层必须经 NewCipher 构造：以继承库内全部输入校验（算法名、密钥长度、
//     nonce/IV 长度、填充校验等），不得绕过 NewCipher 直接调用标准库。
//   - 每次调用新建 mode 对象：不得跨调用复用同一 mode 对象（如固定 IV 的
//     CBC/CFB/OFB 重复 Encrypt 会复用 keystream 导致明文泄露）。
//   - 错误须含格式名前缀：返回的错误应携带本格式标识（如 "gcx1: ..."），
//     便于调用方定位是哪个适配器拒绝。
//   - 无认证格式风险自担：若实现基于无认证模式（ECB/CBC/CTR 等），
//     其安全风险（可篡改、模式泄露等）由适配器作者与调用方自行承担，
//     库本身不内置任何无认证 codec。
type EnvelopeCodec interface {
	// Name 返回注册名，须匹配 ^[a-z][a-z0-9-]{0,63}$，且不得与保留名冲突。
	Name() string
	// Encrypt 使用指定算法（已归一化）与密钥加密明文，输出本格式信封。
	Encrypt(algorithm rootcrypto.Algorithm, key []byte, plaintext []byte, opts ...rootcrypto.Option) ([]byte, error)
	// Decrypt 解密本格式信封，返回明文。
	Decrypt(key []byte, envelope []byte, opts ...rootcrypto.Option) ([]byte, error)
}

// EnvelopeCodecGCX1 内置默认 codec 名（库保留名，不可被应用侧覆盖注册）。
// 应用不注册任何适配器时，EncryptWith/DecryptWith 默认命中该内置实现，
// 与现有 Encrypt/Decrypt 行为完全一致。
const EnvelopeCodecGCX1 = "gcx1"

var (
	// ErrUnknownEnvelopeCodec 查询未注册的 codec 名。
	ErrUnknownEnvelopeCodec = errors.New("envelope codec: unknown codec")
	// ErrEnvelopeCodecExists 注册名已被占用（含保留名），注册永不覆盖。
	ErrEnvelopeCodecExists = errors.New("envelope codec: name already registered")
	// ErrInvalidEnvelopeCodecName 注册名不符合 ^[a-z][a-z0-9-]{0,63}$。
	ErrInvalidEnvelopeCodecName = errors.New("envelope codec: invalid name")
	// ErrInvalidEnvelopeCodec 注册的 codec 为 nil 或其 Name() 为空。
	ErrInvalidEnvelopeCodec = errors.New("envelope codec: invalid codec")
)

// envelopeCodecRegistry 全局注册表：包级变量初始化直接内置 gcx1 codec，
// 不依赖 init()，保证"应用零配置即默认可用"。
var envelopeCodecRegistry = struct {
	mu sync.RWMutex
	m  map[string]EnvelopeCodec
}{m: map[string]EnvelopeCodec{EnvelopeCodecGCX1: gcx1Codec{}}}

// RegisterEnvelopeCodec 注册自定义信封适配器。名称须匹配
// ^[a-z][a-z0-9-]{0,63}$；已占用（含保留名 "gcx1"）时返回
// ErrEnvelopeCodecExists 且**永不覆盖**既有注册。
// 建议在 init() 或启动早期一次性注册，先于首次加解密。
//
// 不得注册 nil 指针：codec 为 nil 或类型化 nil 指针
// （如 (*myCodec)(nil) 经接口传入）均返回 ErrInvalidEnvelopeCodec。
func RegisterEnvelopeCodec(codec EnvelopeCodec) error {
	if codec == nil {
		return ErrInvalidEnvelopeCodec
	}
	// 类型化 nil 指针：codec == nil 为 false，但调用其 Name() 会 panic，
	// 需通过反射显式识别并拒绝。
	if v := reflect.ValueOf(codec); v.Kind() == reflect.Ptr && v.IsNil() {
		return ErrInvalidEnvelopeCodec
	}
	name := codec.Name()
	if name == "" {
		return ErrInvalidEnvelopeCodec
	}
	if !validEnvelopeCodecName(name) {
		return ErrInvalidEnvelopeCodecName
	}

	envelopeCodecRegistry.mu.Lock()
	defer envelopeCodecRegistry.mu.Unlock()
	if _, ok := envelopeCodecRegistry.m[name]; ok {
		return fmt.Errorf("%w: %q", ErrEnvelopeCodecExists, name)
	}
	envelopeCodecRegistry.m[name] = codec
	return nil
}

// EnvelopeCodecByName 按名称查询已注册 codec；未注册返回
// ErrUnknownEnvelopeCodec。内置保留名 "gcx1" 无需注册即可查到。
func EnvelopeCodecByName(name string) (EnvelopeCodec, error) {
	envelopeCodecRegistry.mu.RLock()
	defer envelopeCodecRegistry.mu.RUnlock()
	codec, ok := envelopeCodecRegistry.m[name]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownEnvelopeCodec, name)
	}
	return codec, nil
}

// EnvelopeCodecs 返回已注册 codec 名的排序清单（诊断用）。
func EnvelopeCodecs() []string {
	envelopeCodecRegistry.mu.RLock()
	defer envelopeCodecRegistry.mu.RUnlock()
	names := make([]string, 0, len(envelopeCodecRegistry.m))
	for name := range envelopeCodecRegistry.m {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// EncryptWith 通过指定 codec 加密明文。codec 未注册返回
// ErrUnknownEnvelopeCodec；算法名先经 NormalizeAlgorithm 归一化（失败透传）。
func EncryptWith(codecName string, algorithm rootcrypto.Algorithm, key, plaintext []byte, opts ...rootcrypto.Option) ([]byte, error) {
	codec, err := EnvelopeCodecByName(codecName)
	if err != nil {
		return nil, err
	}
	return codec.Encrypt(algorithm, key, plaintext, opts...)
}

// DecryptWith 通过指定 codec 解密信封。codec 未注册返回
// ErrUnknownEnvelopeCodec。
func DecryptWith(codecName string, key, envelope []byte, opts ...rootcrypto.Option) ([]byte, error) {
	codec, err := EnvelopeCodecByName(codecName)
	if err != nil {
		return nil, err
	}
	return codec.Decrypt(key, envelope, opts...)
}

// validEnvelopeCodecName 校验注册名是否匹配 ^[a-z][a-z0-9-]{0,63}$。
// 手写逐字符校验，避免为正则表达式引入额外依赖与开销。
func validEnvelopeCodecName(name string) bool {
	if len(name) == 0 || len(name) > 64 {
		return false
	}
	if name[0] < 'a' || name[0] > 'z' {
		return false
	}
	for i := 1; i < len(name); i++ {
		c := name[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
			return false
		}
	}
	return true
}

// gcx1Codec 内置默认适配器：纯转发现有 gcx1 实现，一行逻辑不重写。
// 无状态：零字段结构体，天然并发安全。
type gcx1Codec struct{}

// Name 返回内置保留名 "gcx1"。
func (gcx1Codec) Name() string { return EnvelopeCodecGCX1 }

// Encrypt 转发现有 gcx1 Encrypt 实现；opts 中的 WithAAD 提取后
// 转发 EncryptWithAAD。
//
// 选项处理约定（文档化行为）：gcx1 固定使用 GCM 认证加密，仅 AAD 选项
// （WithAAD）生效，其余选项（如 WithPadding/WithIV 等非 GCM 选项）一律
// 静默忽略，不报错也不影响输出。调用方不应依赖被忽略选项产生任何效果。
func (gcx1Codec) Encrypt(algorithm rootcrypto.Algorithm, key []byte, plaintext []byte, opts ...rootcrypto.Option) ([]byte, error) {
	aad := rootcrypto.AADFromOptions(opts...)
	if len(aad) > 0 {
		return EncryptWithAAD(algorithm, key, plaintext, aad)
	}
	return Encrypt(algorithm, key, plaintext)
}

// Decrypt 转发现有 gcx1 Decrypt 实现；opts 中的 WithAAD 提取后
// 转发 DecryptWithAAD。
//
// 选项处理约定（文档化行为）：与 Encrypt 一致，仅 AAD 选项（WithAAD）生效，
// 其余选项静默忽略。
func (gcx1Codec) Decrypt(key []byte, envelope []byte, opts ...rootcrypto.Option) ([]byte, error) {
	aad := rootcrypto.AADFromOptions(opts...)
	if len(aad) > 0 {
		return DecryptWithAAD(key, envelope, aad)
	}
	return Decrypt(key, envelope)
}
