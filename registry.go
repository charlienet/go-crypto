// Package crypto 引擎注册表：契约层的算法引擎挂载点（database/sql driver
// 模式，与 crypto/envelope 的 EnvelopeCodec 注册表同构）。
//
// 算法实现分布在子包（crypto/symmetric、crypto/asym、crypto/agreement、
// crypto/keymgr），各子包在 init() 中经本文件的 Register* 系列函数注册
// 自身实现；根包协议入口（NewCipher/Encrypt/Decrypt/NewAsymmetric/
// NewKeyAgreement/GenerateKeyPair）后续阶段经注册表分发。根包永不
// import 子包，依赖保持单向（子包 → 根包 → common）。
//
// # 两条注册路径（均永不覆盖）
//
//   - blank import（主路径）：如 import _ "github.com/charlienet/go-crypto/symmetric"
//     触发子包 init() 注册默认引擎，根包协议入口即可用；
//   - 显式注册（扩展路径）：应用在 init() 或启动早期调用 Register* 注入
//     自定义引擎（HSM 后端、自定义 ModeExecutor 等）。
//
// 两条路径语义一致：同一键重复注册返回 ErrEngineExists 且**永不覆盖**
// 既有实现，防止两个子包争抢同一键时静默互踩；查询未注册的键返回
// ErrEngineNotRegistered。所有注册/查询均并发安全（RWMutex 保护）。
//
// 注意：本文件为注册表骨架（阶段 2），协议入口尚未切换，仍走原实现路径。
package crypto

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"sync"
)

var (
	// ErrEngineExists 注册键已被占用（含重复 blank import / 显式重复注册）。
	ErrEngineExists = errors.New("crypto: engine already registered")
	// ErrEngineNotRegistered 查询的引擎未注册（多半是调用方未 blank import 对应子包）。
	ErrEngineNotRegistered = errors.New("crypto: engine not registered")
)

// errNilEngine 注册的引擎为 nil（函数工厂为 nil、CipherFactory.New 为 nil、
// 或接口为类型化 nil 指针）时拒绝注册的内部哨兵。
var errNilEngine = errors.New("crypto: nil engine")

// ---- 对称：Cipher 工厂注册表（键 = 算法名，阶段 4 由 NewCipher/GenerateKey/BlockSize 消费）----

// CipherFactory 对称 Cipher 工厂：New 构造算法实例（密钥长度严格校验在
// 工厂内完成），KeySize/IVSize 为 GenerateKey/BlockSize 消费的元数据。
type CipherFactory struct {
	New             func(key []byte) (Cipher, error)
	KeySize, IVSize int
}

// cipherRegistry 对称 Cipher 工厂注册表（键 = 算法名，如 "AES-128"/"SM4"）。
type cipherRegistry struct {
	mu sync.RWMutex
	m  map[string]CipherFactory
}

var cipherFactories = cipherRegistry{m: map[string]CipherFactory{}}

// RegisterCipherFactory 注册对称 Cipher 工厂。键为算法名（建议使用
// NormalizeAlgorithm 规范形式）。已占用时返回 ErrEngineExists 且不覆盖；
// New 为 nil 时返回 errNilEngine。建议在子包 init() 中调用。
func RegisterCipherFactory(algorithm string, f CipherFactory) error {
	if f.New == nil {
		return errNilEngine
	}
	cipherFactories.mu.Lock()
	defer cipherFactories.mu.Unlock()
	if _, ok := cipherFactories.m[algorithm]; ok {
		return fmt.Errorf("%w: %q", ErrEngineExists, algorithm)
	}
	cipherFactories.m[algorithm] = f
	return nil
}

// CipherFactoryFor 按算法名查询 Cipher 工厂；未注册返回 ErrEngineNotRegistered。
func CipherFactoryFor(algorithm string) (CipherFactory, error) {
	cipherFactories.mu.RLock()
	defer cipherFactories.mu.RUnlock()
	f, ok := cipherFactories.m[algorithm]
	if !ok {
		return CipherFactory{}, fmt.Errorf("%w: %q", ErrEngineNotRegistered, algorithm)
	}
	return f, nil
}

// ---- 对称：模式执行器注册表（键 = Mode 枚举，阶段 4 由 Encrypt/Decrypt 消费）----

// ModeExecutor 单一工作模式的加密执行器。由 crypto/symmetric 子包实现
// 六个模式（ECB/CBC/CTR/CFB/OFB/GCM）并注册。
// 实现须无状态，或每次调用新建模式对象：跨消息复用固定 IV/nonce 的
// 模式对象会复用 keystream，直接泄露明文。
type ModeExecutor interface {
	Encrypt(c Cipher, alg Algorithm, cfg *Config, plaintext []byte) ([]byte, error)
	Decrypt(c Cipher, alg Algorithm, cfg *Config, ciphertext []byte) ([]byte, error)
}

// modeRegistry 模式执行器注册表（键 = Mode 枚举）。
type modeRegistry struct {
	mu sync.RWMutex
	m  map[Mode]ModeExecutor
}

var modeExecutors = modeRegistry{m: map[Mode]ModeExecutor{}}

// RegisterModeExecutor 注册模式执行器。键为 Mode 枚举；已占用返回
// ErrEngineExists 且不覆盖。不得注册 nil：ex 为 nil 或类型化 nil 指针
// （如 (*myExecutor)(nil) 经接口传入——ex == nil 判为 false 但调用即
// panic）均返回 errNilEngine。建议在子包 init() 中调用。
func RegisterModeExecutor(mode Mode, ex ModeExecutor) error {
	if ex == nil {
		return errNilEngine
	}
	// 类型化 nil 指针：复用 envelope_codec.go 的反射校验模式
	if v := reflect.ValueOf(ex); v.Kind() == reflect.Pointer && v.IsNil() {
		return errNilEngine
	}
	modeExecutors.mu.Lock()
	defer modeExecutors.mu.Unlock()
	if _, ok := modeExecutors.m[mode]; ok {
		return fmt.Errorf("%w: %q", ErrEngineExists, mode)
	}
	modeExecutors.m[mode] = ex
	return nil
}

// ModeExecutorFor 按模式查询执行器；未注册返回 ErrEngineNotRegistered。
func ModeExecutorFor(mode Mode) (ModeExecutor, error) {
	modeExecutors.mu.RLock()
	defer modeExecutors.mu.RUnlock()
	ex, ok := modeExecutors.m[mode]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrEngineNotRegistered, mode)
	}
	return ex, nil
}

// ---- 非对称工厂（键 = NormalizeAlgorithm 规范名，阶段 3 由 NewAsymmetric 消费）----

// asymmetricRegistry 非对称算法工厂注册表。
type asymmetricRegistry struct {
	mu sync.RWMutex
	m  map[string]func(opts ...AsymOption) (Asymmetric, error)
}

var asymmetricFactories = asymmetricRegistry{m: map[string]func(opts ...AsymOption) (Asymmetric, error){}}

// RegisterAsymmetricFactory 注册非对称算法工厂。键为算法名（NormalizeAlgorithm
// 规范形式，如 "SM2"/"RSA"）。f 为 nil 时返回 errNilEngine；已占用返回
// ErrEngineExists 且不覆盖。建议在子包 init() 中调用。
func RegisterAsymmetricFactory(algorithm string, f func(opts ...AsymOption) (Asymmetric, error)) error {
	if f == nil {
		return errNilEngine
	}
	asymmetricFactories.mu.Lock()
	defer asymmetricFactories.mu.Unlock()
	if _, ok := asymmetricFactories.m[algorithm]; ok {
		return fmt.Errorf("%w: %q", ErrEngineExists, algorithm)
	}
	asymmetricFactories.m[algorithm] = f
	return nil
}

// AsymmetricFactoryFor 按算法名查询非对称算法工厂；未注册返回 ErrEngineNotRegistered。
func AsymmetricFactoryFor(algorithm string) (func(opts ...AsymOption) (Asymmetric, error), error) {
	asymmetricFactories.mu.RLock()
	defer asymmetricFactories.mu.RUnlock()
	creator, ok := asymmetricFactories.m[algorithm]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrEngineNotRegistered, algorithm)
	}
	return creator, nil
}

// ---- 密钥协商工厂（键 = NormalizeAlgorithm 规范名，阶段 3 由 NewKeyAgreement 消费）----

// keyAgreementRegistry 密钥协商工厂注册表。
type keyAgreementRegistry struct {
	mu sync.RWMutex
	m  map[string]func() (KeyAgreement, error)
}

var keyAgreementFactories = keyAgreementRegistry{m: map[string]func() (KeyAgreement, error){}}

// RegisterKeyAgreementFactory 注册密钥协商工厂。键为算法名（NormalizeAlgorithm
// 规范形式，如 "ECDH"/"X25519"）。f 为 nil 时返回 errNilEngine；已占用返回
// ErrEngineExists 且不覆盖。建议在子包 init() 中调用。
func RegisterKeyAgreementFactory(algorithm string, f func() (KeyAgreement, error)) error {
	if f == nil {
		return errNilEngine
	}
	keyAgreementFactories.mu.Lock()
	defer keyAgreementFactories.mu.Unlock()
	if _, ok := keyAgreementFactories.m[algorithm]; ok {
		return fmt.Errorf("%w: %q", ErrEngineExists, algorithm)
	}
	keyAgreementFactories.m[algorithm] = f
	return nil
}

// KeyAgreementFactoryFor 按算法名查询密钥协商工厂；未注册返回 ErrEngineNotRegistered。
func KeyAgreementFactoryFor(algorithm string) (func() (KeyAgreement, error), error) {
	keyAgreementFactories.mu.RLock()
	defer keyAgreementFactories.mu.RUnlock()
	creator, ok := keyAgreementFactories.m[algorithm]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrEngineNotRegistered, algorithm)
	}
	return creator, nil
}

// ---- 密钥对生成器（键 = NormalizeAlgorithm 规范名，阶段 3 由 GenerateKeyPair 消费）----

// keyPairGeneratorRegistry 密钥对生成器注册表。
type keyPairGeneratorRegistry struct {
	mu sync.RWMutex
	m  map[string]func(cfg *KeyGenConfig) (*KeyPair, error)
}

var keyPairGenerators = keyPairGeneratorRegistry{m: map[string]func(cfg *KeyGenConfig) (*KeyPair, error){}}

// RegisterKeyPairGenerator 注册密钥对生成器。键为算法名（NormalizeAlgorithm
// 规范形式）。f 为 nil 时返回 errNilEngine；已占用返回 ErrEngineExists 且
// 不覆盖。建议在子包 init() 中调用。
func RegisterKeyPairGenerator(algorithm string, f func(cfg *KeyGenConfig) (*KeyPair, error)) error {
	if f == nil {
		return errNilEngine
	}
	keyPairGenerators.mu.Lock()
	defer keyPairGenerators.mu.Unlock()
	if _, ok := keyPairGenerators.m[algorithm]; ok {
		return fmt.Errorf("%w: %q", ErrEngineExists, algorithm)
	}
	keyPairGenerators.m[algorithm] = f
	return nil
}

// KeyPairGeneratorFor 按算法名查询密钥对生成器；未注册返回 ErrEngineNotRegistered。
func KeyPairGeneratorFor(algorithm string) (func(cfg *KeyGenConfig) (*KeyPair, error), error) {
	keyPairGenerators.mu.RLock()
	defer keyPairGenerators.mu.RUnlock()
	gen, ok := keyPairGenerators.m[algorithm]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrEngineNotRegistered, algorithm)
	}
	return gen, nil
}

// Engines 返回各注册表已注册键名的排序清单（诊断用，对齐
// envelope.EnvelopeCodecs）：汇总五类注册表全部键，去重后按字典序排序。
// 模式执行器注册表的键（Mode 枚举）以 String() 规范名形式返回。
func Engines() []string {
	seen := make(map[string]struct{})

	cipherFactories.mu.RLock()
	for name := range cipherFactories.m {
		seen[name] = struct{}{}
	}
	cipherFactories.mu.RUnlock()

	modeExecutors.mu.RLock()
	for m := range modeExecutors.m {
		seen[m.String()] = struct{}{}
	}
	modeExecutors.mu.RUnlock()

	asymmetricFactories.mu.RLock()
	for name := range asymmetricFactories.m {
		seen[name] = struct{}{}
	}
	asymmetricFactories.mu.RUnlock()

	keyAgreementFactories.mu.RLock()
	for name := range keyAgreementFactories.m {
		seen[name] = struct{}{}
	}
	keyAgreementFactories.mu.RUnlock()

	keyPairGenerators.mu.RLock()
	for name := range keyPairGenerators.m {
		seen[name] = struct{}{}
	}
	keyPairGenerators.mu.RUnlock()

	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
