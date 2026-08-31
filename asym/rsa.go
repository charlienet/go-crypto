package asym

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/charlienet/go-utils/bytex"
	rootcrypto "github.com/charlienet/go-crypto"
)

type rsa_algo struct {
	prk  *rsa.PrivateKey
	puk  *rsa.PublicKey
	hash crypto.Hash
	bits int
}

// newRSA 构造 RSA 非对称算法实例（注册表工厂签名）。
func newRSA(opts ...rootcrypto.AsymOption) (rootcrypto.Asymmetric, error) {
	cfg := &rootcrypto.AsymConfig{}
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, err
		}
	}

	algo := &rsa_algo{
		hash: crypto.SHA256,
		bits: 2048,
	}

	// 优先使用密钥对象
	if cfg.PrivateKeyObject != nil {
		rsaKey, ok := cfg.PrivateKeyObject.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("not an RSA private key")
		}
		algo.prk = rsaKey
	} else if cfg.PrivateKey != "" {
		if err := algo.WithPrivateKey(cfg.PrivateKey); err != nil {
			return nil, err
		}
	}

	if cfg.PublicKeyObject != nil {
		rsaKey, ok := cfg.PublicKeyObject.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("not an RSA public key")
		}
		algo.puk = rsaKey
	} else if cfg.PublicKey != "" {
		if err := algo.WithPublicKey(cfg.PublicKey); err != nil {
			return nil, err
		}
	}

	return algo, nil
}

func (s *rsa_algo) Name() string {
	return "RSA"
}

func (s *rsa_algo) GenerateKey() (rootcrypto.KeyPair, error) {
	key, err := rsa.GenerateKey(rand.Reader, s.bits)
	if err != nil {
		return rootcrypto.KeyPair{}, err
	}

	s.prk = key

	return rootcrypto.KeyPair{
		PrivateKey: key,
		PublicKey:  &key.PublicKey,
	}, nil
}

func (s *rsa_algo) WithPrivateKey(privateKey string) error {
	prkBytes, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		return err
	}

	// 先尝试 PKCS1 格式
	prk, err := x509.ParsePKCS1PrivateKey(prkBytes)
	if err == nil {
		s.prk = prk
	} else {
		// 再尝试 PKCS8 格式
		key, err := x509.ParsePKCS8PrivateKey(prkBytes)
		if err != nil {
			return err
		}

		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return errors.New("not an RSA private key")
		}

		s.prk = rsaKey
	}

	// 弱密钥校验：RSA 长度低于 2048-bit 视为不安全（如 512/1024-bit 已被视为可破解），直接拒绝
	if s.prk.N.BitLen() < 2048 {
		bits := s.prk.N.BitLen()
		s.prk = nil
		return fmt.Errorf("RSA private key too weak: %d bits, minimum required is 2048 bits", bits)
	}
	return nil
}

func (s *rsa_algo) WithPublicKey(publicKey string) error {
	pubBytes, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return err
	}

	k, err := x509.ParsePKIXPublicKey(pubBytes)
	if err != nil {
		return err
	}

	puk, ok := k.(*rsa.PublicKey)
	if !ok {
		return errors.New("not an RSA public key")
	}

	// 弱密钥校验：与私钥策略对称，公钥低于 2048-bit 同样拒绝
	if puk.N.BitLen() < 2048 {
		bits := puk.N.BitLen()
		return fmt.Errorf("RSA public key too weak: %d bits, minimum required is 2048 bits", bits)
	}

	s.puk = puk
	return nil
}

func (s *rsa_algo) ExportPublicKey() (string, error) {
	// 与 ECDSA 行为对齐：私钥未设置时回退到仅注入的公钥
	if s.prk == nil && s.puk == nil {
		return "", errors.New("no key set")
	}

	pub := s.puk
	if pub == nil {
		pub = &s.prk.PublicKey
	}

	out, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(out), nil
}

// OAEP 加密标签：空标签（无上下文绑定）。
// 使用函数内字面量 []byte{} 而非包级可变变量，避免包级状态被同包代码篡改。
func (r *rsa_algo) Encrypt(msg []byte) (bytex.Bytes, error) {
	if r.puk == nil {
		return nil, errors.New("RSA public key not set")
	}

	cipher, err := rsa.EncryptOAEP(r.hash.New(), rand.Reader, r.puk, msg, []byte{})
	return cipher, err
}

func (r *rsa_algo) Decrypt(msg []byte) (bytex.Bytes, error) {
	if r.prk == nil {
		return nil, errors.New("RSA private key not set")
	}

	// 校验私钥一致性：KeyPair.Reset 清零后同指针实例可被检测到，
	// 避免静默产出无效结果。Validate 只做一致性校验，不修改密钥。
	if err := r.prk.Validate(); err != nil {
		return nil, fmt.Errorf("RSA private key is invalid: %w", err)
	}

	plain, err := rsa.DecryptOAEP(r.hash.New(), rand.Reader, r.prk, msg, []byte{})
	return plain, err
}

func (r *rsa_algo) Sign(data []byte) (bytex.Bytes, error) {
	if r.prk == nil {
		return nil, errors.New("RSA private key not set")
	}

	// 校验私钥一致性：KeyPair.Reset 清零后同指针实例可被检测到，
	// 避免静默产出无效签名。Validate 只做一致性校验，不修改密钥。
	if err := r.prk.Validate(); err != nil {
		return nil, fmt.Errorf("RSA private key is invalid: %w", err)
	}

	h := r.hash.New()
	h.Write(data)
	hashed := h.Sum(nil)

	// 显式指定 PSS 盐长度为 hash 长度（PSSSaltLengthEqualsHash）：
	// 不依赖 SaltLengthAuto 的隐式推导，语义明确。
	// 在 2048 位密钥 + SHA-256 下与 SaltLengthAuto 输出一致，行为不变。
	signature, err := rsa.SignPSS(rand.Reader, r.prk, r.hash, hashed, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       r.hash,
	})
	return signature, err
}

// Verify 校验签名。
//
// 注意：返回 false 无法区分"签名无效"与"公钥未设置"两种情况，
// 调用方在依赖验证结果前应先确认公钥已配置（如先调用 ExportPublicKey
// 或构造时注入公钥）。
func (r *rsa_algo) Verify(data, signature []byte) bool {
	if r.puk == nil {
		return false
	}

	h := r.hash.New()
	h.Write(data)
	hashed := h.Sum(nil)

	// 验证侧显式使用 PSSSaltLengthAuto（自动探测盐长）：
	// 兼容标准库默认（Auto）输出的最大盐长签名与本库 EqualsHash 签名。
	// 盐策略从此处显式可见，不再依赖 opts=nil 隐式。
	err := rsa.VerifyPSS(r.puk, r.hash, hashed, signature, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       r.hash,
	})
	return err == nil
}
