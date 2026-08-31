package crypto_test

// 根包协议入口（NewAsymmetric/NewKeyAgreement/GenerateKeyPair）经注册表
// 分发的端到端行为测试：blank import 四个子包触发 init() 注册默认引擎，
// 验证预定义算法正常路径、子集外拒绝、未注册提示、开放扩展与哨兵错误判定。
// Engines() 汇总断言覆盖对称（算法+模式）与非对称全部注册键。

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/charlienet/go-utils/bytex"
	"github.com/charlienet/go-crypto"

	_ "github.com/charlienet/go-crypto/agreement"
	_ "github.com/charlienet/go-crypto/asym"
	_ "github.com/charlienet/go-crypto/keymgr"
	_ "github.com/charlienet/go-crypto/symmetric"
)

// stubAsymmetric 实现 crypto.Asymmetric 接口的最小桩（仿 registry_test.go 风格）。
type stubAsymmetric struct{}

func (s *stubAsymmetric) GenerateKey() (crypto.KeyPair, error) { return crypto.KeyPair{}, nil }
func (s *stubAsymmetric) WithPrivateKey(string) error          { return nil }
func (s *stubAsymmetric) WithPublicKey(string) error           { return nil }
func (s *stubAsymmetric) ExportPublicKey() (string, error)     { return "", nil }
func (s *stubAsymmetric) Name() string                         { return "stub-asym" }
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

// TestProtocol_PredefinedAlgorithms 预定义算法正常路径：三个协议入口
// 经注册表分发均构造/生成成功（非 nil）。
func TestProtocol_PredefinedAlgorithms(t *testing.T) {
	// 非对称实例：四预定义算法均可构造
	for _, alg := range []crypto.AsymmetricAlgorithm{crypto.RSA, crypto.ECDSA, crypto.ED25519, crypto.SM2} {
		a, err := crypto.NewAsymmetric(alg)
		if err != nil {
			t.Fatalf("NewAsymmetric(%s) 失败: %v", alg, err)
		}
		if a == nil {
			t.Fatalf("NewAsymmetric(%s) 返回 nil 实例", alg)
		}
	}

	// 密钥协商：ECDH/X25519 构造成功
	for _, alg := range []crypto.AsymmetricAlgorithm{crypto.ECDH, crypto.X25519} {
		ka, err := crypto.NewKeyAgreement(alg)
		if err != nil {
			t.Fatalf("NewKeyAgreement(%s) 失败: %v", alg, err)
		}
		if ka == nil {
			t.Fatalf("NewKeyAgreement(%s) 返回 nil 实例", alg)
		}
	}

	// 密钥对生成：四预定义算法均成功且密钥对非 nil
	for _, alg := range []crypto.AsymmetricAlgorithm{crypto.RSA, crypto.ECDSA, crypto.ED25519, crypto.SM2} {
		kp, err := crypto.GenerateKeyPair(alg)
		if err != nil {
			t.Fatalf("GenerateKeyPair(%s) 失败: %v", alg, err)
		}
		if kp == nil {
			t.Fatalf("GenerateKeyPair(%s) 返回 nil 密钥对", alg)
		}
	}
}

// TestProtocol_SubsetRejected 子集外拒绝：预定义但属他类入口的算法
// 明确报错，且不附带 "no engine registered" 导入提示。
func TestProtocol_SubsetRejected(t *testing.T) {
	// NewAsymmetric 拒绝密钥协商算法（ECDH）
	_, err := crypto.NewAsymmetric(crypto.ECDH)
	if err == nil || !strings.Contains(err.Error(), "unsupported asymmetric algorithm") {
		t.Fatalf("NewAsymmetric(ECDH) 错误不符: %v", err)
	}
	if strings.Contains(err.Error(), "no engine registered") {
		t.Fatalf("NewAsymmetric(ECDH) 不应含导入提示: %v", err)
	}

	// NewKeyAgreement 拒绝非对称加解密算法（RSA）
	_, err = crypto.NewKeyAgreement(crypto.RSA)
	if err == nil || !strings.Contains(err.Error(), "unsupported key agreement algorithm") {
		t.Fatalf("NewKeyAgreement(RSA) 错误不符: %v", err)
	}
	if strings.Contains(err.Error(), "no engine registered") {
		t.Fatalf("NewKeyAgreement(RSA) 不应含导入提示: %v", err)
	}

	// GenerateKeyPair 拒绝密钥协商算法（ECDH）
	_, err = crypto.GenerateKeyPair(crypto.ECDH)
	if err == nil || !strings.Contains(err.Error(), "unsupported algorithm") {
		t.Fatalf("GenerateKeyPair(ECDH) 错误不符: %v", err)
	}
	if strings.Contains(err.Error(), "no engine registered") {
		t.Fatalf("GenerateKeyPair(ECDH) 不应含导入提示: %v", err)
	}
}

// TestProtocol_NotRegistered 未注册错误路径：非预定义值未命中注册表，
// 三个入口分别提示导入对应引擎子包。
func TestProtocol_NotRegistered(t *testing.T) {
	_, err := crypto.NewAsymmetric(crypto.AsymmetricAlgorithm("INVALID"))
	if err == nil || !strings.Contains(err.Error(), "no engine registered for") || !strings.Contains(err.Error(), "github.com/charlienet/go-crypto/asym") {
		t.Fatalf("NewAsymmetric(INVALID) 错误不符: %v", err)
	}

	_, err = crypto.NewKeyAgreement(crypto.AsymmetricAlgorithm("INVALID"))
	if err == nil || !strings.Contains(err.Error(), "no engine registered for") || !strings.Contains(err.Error(), "github.com/charlienet/go-crypto/agreement") {
		t.Fatalf("NewKeyAgreement(INVALID) 错误不符: %v", err)
	}

	_, err = crypto.GenerateKeyPair(crypto.AsymmetricAlgorithm("INVALID"))
	if err == nil || !strings.Contains(err.Error(), "no engine registered for") || !strings.Contains(err.Error(), "github.com/charlienet/go-crypto/keymgr") {
		t.Fatalf("GenerateKeyPair(INVALID) 错误不符: %v", err)
	}
}

// TestProtocol_CustomExtension 开放扩展路径：显式注册自定义非对称引擎后，
// NewAsymmetric 经注册表命中并执行。注册键用自定义名避免污染既有键；
// 注册表永不覆盖且键唯一，测试结束后无需注销。
func TestProtocol_CustomExtension(t *testing.T) {
	const alg = "TEST-X"
	_ = crypto.RegisterAsymmetricFactory(alg, func(opts ...crypto.AsymOption) (crypto.Asymmetric, error) {
		return &stubAsymmetric{}, nil
	})

	a, err := crypto.NewAsymmetric(crypto.AsymmetricAlgorithm(alg))
	if err != nil {
		t.Fatalf("NewAsymmetric(%s) 失败: %v", alg, err)
	}
	if a.Name() != "stub-asym" {
		t.Fatalf("自定义引擎未命中: Name()=%q, want %q", a.Name(), "stub-asym")
	}
}

// TestProtocol_Engines Engines() 汇总清单须包含四个子包注册的全部键：
// 非对称（asym）、密钥协商（agreement）、密钥对生成（keymgr，与 asym 同键去重）
// 与对称（symmetric，7 算法键 + 6 模式键）。
func TestProtocol_Engines(t *testing.T) {
	engines := crypto.Engines()
	for _, want := range []string{
		// 非对称/密钥协商/密钥对生成键
		"RSA", "ECDSA", "ED25519", "SM2", "ECDH", "X25519",
		// 对称算法键（cipher 注册表）
		"SM4", "AES", "AES-128", "AES-192", "AES-256", "DES", "3DES",
		// 对称工作模式键（mode 注册表，Mode 枚举 String() 规范名）
		"GCM", "CBC", "ECB", "CFB", "OFB", "CTR",
	} {
		if !slices.Contains(engines, want) {
			t.Fatalf("Engines() 缺少 %q: %v", want, engines)
		}
	}
}

// TestProtocol_ErrEngineNotRegistered 查询函数返回的包装错误可用
// errors.Is 判定 ErrEngineNotRegistered 哨兵。
func TestProtocol_ErrEngineNotRegistered(t *testing.T) {
	if _, err := crypto.AsymmetricFactoryFor("INVALID"); !errors.Is(err, crypto.ErrEngineNotRegistered) {
		t.Fatalf("AsymmetricFactoryFor 未包装 ErrEngineNotRegistered: %v", err)
	}
	if _, err := crypto.KeyAgreementFactoryFor("INVALID"); !errors.Is(err, crypto.ErrEngineNotRegistered) {
		t.Fatalf("KeyAgreementFactoryFor 未包装 ErrEngineNotRegistered: %v", err)
	}
	if _, err := crypto.KeyPairGeneratorFor("INVALID"); !errors.Is(err, crypto.ErrEngineNotRegistered) {
		t.Fatalf("KeyPairGeneratorFor 未包装 ErrEngineNotRegistered: %v", err)
	}
}
