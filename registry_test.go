package crypto

import (
	"crypto"
	"crypto/cipher"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sync"
	"testing"

	"github.com/charlienet/go-utils/bytex"
)

// ---- 测试桩：实现各契约接口的最小可注册类型 ----

// stubCipher 实现 Cipher 接口的最小桩：仅记录身份 id，方法不执行实际加解密。
type stubCipher struct{ id int }

func (s *stubCipher) Block() cipher.Block                    { return nil }
func (s *stubCipher) BlockSize() int                         { return 16 }
func (s *stubCipher) IVSize() int                            { return 16 }
func (s *stubCipher) NewCTR(iv []byte) (StreamCipher, error) { return nil, nil }
func (s *stubCipher) NewGCM(nonce []byte, opts ...Option) (CipherMode, error) {
	return nil, nil
}
func (s *stubCipher) NewGCMWithRandomNonce() (CipherMode, error) { return nil, nil }
func (s *stubCipher) NewCBC(iv []byte, opts ...Option) (CipherMode, error) {
	return nil, nil
}
func (s *stubCipher) NewCBCWithRandomIV(opts ...Option) (CipherMode, error) {
	return nil, nil
}
func (s *stubCipher) NewECB(opts ...Option) (CipherMode, error) { return nil, nil }
func (s *stubCipher) NewCFB(iv []byte, opts ...Option) (CipherMode, error) {
	return nil, nil
}
func (s *stubCipher) NewCFBWithRandomIV(opts ...Option) (CipherMode, error) {
	return nil, nil
}
func (s *stubCipher) NewOFB(iv []byte, opts ...Option) (CipherMode, error) {
	return nil, nil
}
func (s *stubCipher) NewOFBWithRandomIV(opts ...Option) (CipherMode, error) {
	return nil, nil
}

// stubModeExecutor 实现 ModeExecutor 接口的最小桩：透传明文/密文。
type stubModeExecutor struct{ id int }

func (s *stubModeExecutor) Encrypt(c Cipher, alg Algorithm, cfg *Config, plaintext []byte) ([]byte, error) {
	return append([]byte(nil), plaintext...), nil
}
func (s *stubModeExecutor) Decrypt(c Cipher, alg Algorithm, cfg *Config, ciphertext []byte) ([]byte, error) {
	return append([]byte(nil), ciphertext...), nil
}

// stubAsymmetric 实现 Asymmetric 接口的最小桩。
type stubAsymmetric struct{ id int }

func (s *stubAsymmetric) GenerateKey() (KeyPair, error) { return KeyPair{}, nil }
func (s *stubAsymmetric) WithPrivateKey(string) error   { return nil }
func (s *stubAsymmetric) WithPublicKey(string) error    { return nil }
func (s *stubAsymmetric) ExportPublicKey() (string, error) {
	return "", nil
}
func (s *stubAsymmetric) Name() string { return "stub-asym" }
func (s *stubAsymmetric) Encrypt(msg []byte) (bytex.Bytes, error) {
	return nil, nil
}
func (s *stubAsymmetric) Decrypt(ciphertext []byte) (bytex.Bytes, error) {
	return nil, nil
}
func (s *stubAsymmetric) Sign(msg []byte) (bytex.Bytes, error) {
	return nil, nil
}
func (s *stubAsymmetric) Verify(msg, sign []byte) bool { return true }

// stubKeyAgreement 实现 KeyAgreement 接口的最小桩。
type stubKeyAgreement struct{ id int }

func (s *stubKeyAgreement) GenerateKey() (*KeyPair, error) { return &KeyPair{}, nil }
func (s *stubKeyAgreement) WithPrivateKey(key crypto.PrivateKey) error {
	return nil
}
func (s *stubKeyAgreement) DeriveSharedSecret(peer crypto.PublicKey) ([]byte, error) {
	return nil, nil
}
func (s *stubKeyAgreement) Name() string { return "stub-ka" }

// sameFunc 判断两个函数是否为同一函数（经 reflect 比较代码入口指针；
// 函数类型不能直接 == 比较，测试专用）。
func sameFunc(a, b any) bool {
	return reflect.ValueOf(a).Pointer() == reflect.ValueOf(b).Pointer()
}

// ---- 对称：Cipher 工厂注册表 ----

func TestRegisterCipherFactory(t *testing.T) {
	const alg = "TEST-REG-CIPHER"

	f1 := CipherFactory{
		New:     func(key []byte) (Cipher, error) { return &stubCipher{id: 1}, nil },
		KeySize: 16, IVSize: 16,
	}
	f2 := CipherFactory{
		New:     func(key []byte) (Cipher, error) { return &stubCipher{id: 2}, nil },
		KeySize: 32, IVSize: 32,
	}

	if err := RegisterCipherFactory(alg, f1); err != nil {
		t.Fatalf("首次注册 %q 失败: %v", alg, err)
	}

	// 正常注册 + 查询命中：元数据与工厂均可取回
	got, err := CipherFactoryFor(alg)
	if err != nil {
		t.Fatalf("查询 %q 失败: %v", alg, err)
	}
	if got.KeySize != 16 || got.IVSize != 16 {
		t.Fatalf("查询 %q 元数据不符: KeySize=%d IVSize=%d, want 16/16", alg, got.KeySize, got.IVSize)
	}
	c, err := got.New(nil)
	if err != nil {
		t.Fatalf("查询返回的工厂调用失败: %v", err)
	}
	if sc, ok := c.(*stubCipher); !ok || sc.id != 1 {
		t.Fatalf("查询返回的工厂未命中首注册实现: %v", c)
	}

	// 重复注册：返回 ErrEngineExists 且不覆盖首值
	err = RegisterCipherFactory(alg, f2)
	if !errors.Is(err, ErrEngineExists) {
		t.Fatalf("重复注册应返回 ErrEngineExists, got: %v", err)
	}
	got, err = CipherFactoryFor(alg)
	if err != nil {
		t.Fatalf("重复注册后查询失败: %v", err)
	}
	if got.KeySize != 16 {
		t.Fatalf("重复注册覆盖了首值: KeySize=%d, want 16", got.KeySize)
	}
	c, err = got.New(nil)
	if err != nil {
		t.Fatalf("重复注册后首工厂调用失败: %v", err)
	}
	if sc, ok := c.(*stubCipher); !ok || sc.id != 1 {
		t.Fatalf("重复注册后首工厂被替换: %v", c)
	}

	// 未注册查询
	if _, err := CipherFactoryFor("TEST-REG-CIPHER-NONE"); !errors.Is(err, ErrEngineNotRegistered) {
		t.Fatalf("未注册查询应返回 ErrEngineNotRegistered, got: %v", err)
	}

	// nil 工厂拒绝（New 为 nil）
	if err := RegisterCipherFactory("TEST-REG-CIPHER-NIL", CipherFactory{}); !errors.Is(err, errNilEngine) {
		t.Fatalf("nil 工厂应返回 errNilEngine, got: %v", err)
	}
}

// ---- 对称：模式执行器注册表 ----

func TestRegisterModeExecutor(t *testing.T) {
	const (
		mode = Mode(240) // 自定义枚举值，避开 ECB..GCM（1..6）
		miss = Mode(241)
	)
	ex1 := &stubModeExecutor{id: 1}
	ex2 := &stubModeExecutor{id: 2}

	if err := RegisterModeExecutor(mode, ex1); err != nil {
		t.Fatalf("首次注册失败: %v", err)
	}

	// 正常注册 + 查询命中：接口相等 + 可调用
	got, err := ModeExecutorFor(mode)
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if got != ex1 {
		t.Fatalf("查询未命中首注册执行器: got %v, want %v", got, ex1)
	}
	out, err := got.Encrypt(nil, AES128, &Config{}, []byte("pt"))
	if err != nil || string(out) != "pt" {
		t.Fatalf("查询返回的执行器不可用: err=%v out=%q", err, out)
	}

	// 重复注册：返回 ErrEngineExists 且不覆盖首值
	err = RegisterModeExecutor(mode, ex2)
	if !errors.Is(err, ErrEngineExists) {
		t.Fatalf("重复注册应返回 ErrEngineExists, got: %v", err)
	}
	if got, _ := ModeExecutorFor(mode); got != ex1 {
		t.Fatalf("重复注册覆盖了首值")
	}

	// 未注册查询
	if _, err := ModeExecutorFor(miss); !errors.Is(err, ErrEngineNotRegistered) {
		t.Fatalf("未注册查询应返回 ErrEngineNotRegistered, got: %v", err)
	}

	// nil 接口拒绝
	if err := RegisterModeExecutor(Mode(242), nil); !errors.Is(err, errNilEngine) {
		t.Fatalf("nil 执行器应返回 errNilEngine, got: %v", err)
	}
	// 类型化 nil 指针拒绝（ex == nil 为 false，须反射识别）
	var typedNil *stubModeExecutor
	if err := RegisterModeExecutor(Mode(243), typedNil); !errors.Is(err, errNilEngine) {
		t.Fatalf("类型化 nil 执行器应返回 errNilEngine, got: %v", err)
	}
}

// ---- 非对称工厂注册表 ----

func TestRegisterAsymmetricFactory(t *testing.T) {
	const alg = "TEST-REG-ASYM"
	f1 := func(opts ...AsymOption) (Asymmetric, error) { return &stubAsymmetric{id: 1}, nil }
	f2 := func(opts ...AsymOption) (Asymmetric, error) { return &stubAsymmetric{id: 2}, nil }

	if err := RegisterAsymmetricFactory(alg, f1); err != nil {
		t.Fatalf("首次注册失败: %v", err)
	}
	// 白盒验证注册值保留（函数指针比较）
	if !sameFunc(asymmetricFactories.m[alg], f1) {
		t.Fatalf("asymmetricFactories[%q] 与首注册工厂不一致", alg)
	}
	a, err := asymmetricFactories.m[alg]()
	if err != nil {
		t.Fatalf("注册的工厂调用失败: %v", err)
	}
	if sa, ok := a.(*stubAsymmetric); !ok || sa.id != 1 {
		t.Fatalf("注册的工厂未命中首注册实现: %v", a)
	}

	// 重复注册：返回 ErrEngineExists 且不覆盖首值
	err = RegisterAsymmetricFactory(alg, f2)
	if !errors.Is(err, ErrEngineExists) {
		t.Fatalf("重复注册应返回 ErrEngineExists, got: %v", err)
	}
	if !sameFunc(asymmetricFactories.m[alg], f1) {
		t.Fatalf("重复注册覆盖了首值")
	}

	// nil 工厂拒绝
	if err := RegisterAsymmetricFactory("TEST-REG-ASYM-NIL", nil); !errors.Is(err, errNilEngine) {
		t.Fatalf("nil 工厂应返回 errNilEngine, got: %v", err)
	}
}

// ---- 密钥协商工厂注册表 ----

func TestRegisterKeyAgreementFactory(t *testing.T) {
	const alg = "TEST-REG-KA"
	f1 := func() (KeyAgreement, error) { return &stubKeyAgreement{id: 1}, nil }
	f2 := func() (KeyAgreement, error) { return &stubKeyAgreement{id: 2}, nil }

	if err := RegisterKeyAgreementFactory(alg, f1); err != nil {
		t.Fatalf("首次注册失败: %v", err)
	}
	if !sameFunc(keyAgreementFactories.m[alg], f1) {
		t.Fatalf("keyAgreementFactories[%q] 与首注册工厂不一致", alg)
	}
	ka, err := keyAgreementFactories.m[alg]()
	if err != nil {
		t.Fatalf("注册的工厂调用失败: %v", err)
	}
	if ska, ok := ka.(*stubKeyAgreement); !ok || ska.id != 1 {
		t.Fatalf("注册的工厂未命中首注册实现: %v", ka)
	}

	err = RegisterKeyAgreementFactory(alg, f2)
	if !errors.Is(err, ErrEngineExists) {
		t.Fatalf("重复注册应返回 ErrEngineExists, got: %v", err)
	}
	if !sameFunc(keyAgreementFactories.m[alg], f1) {
		t.Fatalf("重复注册覆盖了首值")
	}

	if err := RegisterKeyAgreementFactory("TEST-REG-KA-NIL", nil); !errors.Is(err, errNilEngine) {
		t.Fatalf("nil 工厂应返回 errNilEngine, got: %v", err)
	}
}

// ---- 密钥对生成器注册表 ----

func TestRegisterKeyPairGenerator(t *testing.T) {
	const alg = "TEST-REG-KP"
	f1 := func(cfg *KeyGenConfig) (*KeyPair, error) { return &KeyPair{}, nil }
	f2 := func(cfg *KeyGenConfig) (*KeyPair, error) { return &KeyPair{}, nil }

	if err := RegisterKeyPairGenerator(alg, f1); err != nil {
		t.Fatalf("首次注册失败: %v", err)
	}
	if !sameFunc(keyPairGenerators.m[alg], f1) {
		t.Fatalf("keyPairGenerators[%q] 与首注册工厂不一致", alg)
	}
	kp, err := keyPairGenerators.m[alg](&KeyGenConfig{})
	if err != nil || kp == nil {
		t.Fatalf("注册的生成器调用失败: err=%v kp=%v", err, kp)
	}

	err = RegisterKeyPairGenerator(alg, f2)
	if !errors.Is(err, ErrEngineExists) {
		t.Fatalf("重复注册应返回 ErrEngineExists, got: %v", err)
	}
	if !sameFunc(keyPairGenerators.m[alg], f1) {
		t.Fatalf("重复注册覆盖了首值")
	}

	if err := RegisterKeyPairGenerator("TEST-REG-KP-NIL", nil); !errors.Is(err, errNilEngine) {
		t.Fatalf("nil 生成器应返回 errNilEngine, got: %v", err)
	}
}

// ---- Engines：跨注册表汇总、去重、排序 ----

func TestEngines(t *testing.T) {
	// 键名唯一，注册不会失败；忽略返回值
	_ = RegisterCipherFactory("TEST-REG-ENG-ZETA", CipherFactory{New: func(key []byte) (Cipher, error) { return &stubCipher{}, nil }, KeySize: 16, IVSize: 16})
	_ = RegisterCipherFactory("TEST-REG-ENG-ALPHA", CipherFactory{New: func(key []byte) (Cipher, error) { return &stubCipher{}, nil }, KeySize: 16, IVSize: 16})
	// GCM：真实 Mode 枚举键，验证以 String() 规范名输出
	_ = RegisterModeExecutor(GCM, &stubModeExecutor{})
	// ENG-BETA 同时注册到非对称与协商注册表：验证跨注册表去重
	_ = RegisterAsymmetricFactory("TEST-REG-ENG-BETA", func(opts ...AsymOption) (Asymmetric, error) { return &stubAsymmetric{}, nil })
	_ = RegisterKeyAgreementFactory("TEST-REG-ENG-BETA", func() (KeyAgreement, error) { return &stubKeyAgreement{}, nil })
	_ = RegisterKeyPairGenerator("TEST-REG-ENG-GAMMA", func(cfg *KeyGenConfig) (*KeyPair, error) { return &KeyPair{}, nil })

	got := Engines()
	if len(got) == 0 {
		t.Fatal("Engines() 返回空清单")
	}
	// 升序且相邻不相等（同时覆盖排序与去重）
	for i := 1; i < len(got); i++ {
		if got[i-1] >= got[i] {
			t.Fatalf("Engines() 未排序或未去重: %v", got)
		}
	}
	for _, want := range []string{
		"TEST-REG-ENG-ALPHA", "TEST-REG-ENG-BETA",
		"TEST-REG-ENG-GAMMA", "TEST-REG-ENG-ZETA", "GCM",
	} {
		if !slices.Contains(got, want) {
			t.Fatalf("Engines() 缺少 %q: %v", want, got)
		}
	}
}

// ---- 并发：多 goroutine 并发注册不同键 + 并发查询（-race 覆盖）----

func TestRegistryConcurrent(t *testing.T) {
	const n = 50

	// 记录测试前的基线键数（测试顺序执行，此前测试可能已注册若干键），
	// 断言增量而非全局总数，避免依赖测试执行顺序。
	base := struct {
		cipher, mode, asym, ka, kp int
	}{
		cipher: len(cipherFactories.m),
		mode:   len(modeExecutors.m),
		asym:   len(asymmetricFactories.m),
		ka:     len(keyAgreementFactories.m),
		kp:     len(keyPairGenerators.m),
	}

	var wg sync.WaitGroup
	wg.Add(n)
	for i := range n {
		go func(i int) {
			defer wg.Done()
			alg := fmt.Sprintf("TEST-REG-CONC-C-%d", i)
			mode := Mode(300 + i)

			// 五类注册表各并发注册一键
			if err := RegisterCipherFactory(alg, CipherFactory{New: func(key []byte) (Cipher, error) { return &stubCipher{}, nil }, KeySize: 16, IVSize: 16}); err != nil {
				t.Errorf("并发注册 cipher 失败: %v", err)
				return
			}
			if err := RegisterModeExecutor(mode, &stubModeExecutor{id: i}); err != nil {
				t.Errorf("并发注册 mode 失败: %v", err)
				return
			}
			if err := RegisterAsymmetricFactory(fmt.Sprintf("TEST-REG-CONC-A-%d", i), func(opts ...AsymOption) (Asymmetric, error) { return &stubAsymmetric{}, nil }); err != nil {
				t.Errorf("并发注册 asymmetric 失败: %v", err)
				return
			}
			if err := RegisterKeyAgreementFactory(fmt.Sprintf("TEST-REG-CONC-K-%d", i), func() (KeyAgreement, error) { return &stubKeyAgreement{}, nil }); err != nil {
				t.Errorf("并发注册 keyagreement 失败: %v", err)
				return
			}
			if err := RegisterKeyPairGenerator(fmt.Sprintf("TEST-REG-CONC-P-%d", i), func(cfg *KeyGenConfig) (*KeyPair, error) { return &KeyPair{}, nil }); err != nil {
				t.Errorf("并发注册 keypair 失败: %v", err)
				return
			}

			// 并发查询命中
			if f, err := CipherFactoryFor(alg); err != nil || f.New == nil {
				t.Errorf("并发查询 cipher 失败: err=%v f=%v", err, f)
				return
			}
			if ex, err := ModeExecutorFor(mode); err != nil || ex == nil {
				t.Errorf("并发查询 mode 失败: err=%v ex=%v", err, ex)
				return
			}
			// 并发查询未命中
			if _, err := CipherFactoryFor(fmt.Sprintf("TEST-REG-CONC-MISS-%d", i)); !errors.Is(err, ErrEngineNotRegistered) {
				t.Errorf("并发查询未注册键错误不符: %v", err)
				return
			}
			if _, err := ModeExecutorFor(Mode(400 + i)); !errors.Is(err, ErrEngineNotRegistered) {
				t.Errorf("并发查询未注册 mode 错误不符: %v", err)
				return
			}
		}(i)
	}
	wg.Wait()

	// 全部注册完成后校验各注册表键数增量（此时无并发写，读安全）
	if got := len(cipherFactories.m); got != base.cipher+n {
		t.Fatalf("并发注册后 cipher 注册表键数增量 = %d, want %d", got-base.cipher, n)
	}
	if got := len(modeExecutors.m); got != base.mode+n {
		t.Fatalf("并发注册后 mode 注册表键数增量 = %d, want %d", got-base.mode, n)
	}
	if got := len(asymmetricFactories.m); got != base.asym+n {
		t.Fatalf("并发注册后 asymmetric 注册表键数增量 = %d, want %d", got-base.asym, n)
	}
	if got := len(keyAgreementFactories.m); got != base.ka+n {
		t.Fatalf("并发注册后 keyagreement 注册表键数增量 = %d, want %d", got-base.ka, n)
	}
	if got := len(keyPairGenerators.m); got != base.kp+n {
		t.Fatalf("并发注册后 keypair 注册表键数增量 = %d, want %d", got-base.kp, n)
	}
}
