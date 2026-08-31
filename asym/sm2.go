package asym

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"errors"

	"github.com/charlienet/go-utils/bytex"
	rootcrypto "github.com/charlienet/go-crypto"
	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

type sm2_algo struct {
	prk *sm2.PrivateKey
	puk *ecdsa.PublicKey
}

// newSM2 构造 SM2 非对称算法实例（注册表工厂签名）。
func newSM2(opts ...rootcrypto.AsymOption) (rootcrypto.Asymmetric, error) {
	cfg := &rootcrypto.AsymConfig{}
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, err
		}
	}

	s := &sm2_algo{}

	// 优先使用密钥对象
	if cfg.PrivateKeyObject != nil {
		// First try direct sm2.PrivateKey
		if sm2Key, ok := cfg.PrivateKeyObject.(*sm2.PrivateKey); ok {
			s.prk = sm2Key
		} else {
			// Check if it's an ecdsa.PrivateKey that is actually an SM2 key
			ecdsaKey, ok := cfg.PrivateKeyObject.(*ecdsa.PrivateKey)
			if !ok {
				return nil, errors.New("not an SM2 private key")
			}
			// Check if it's actually an SM2 key by checking the public key
			if !sm2.IsSM2PublicKey(&ecdsaKey.PublicKey) {
				return nil, errors.New("not an SM2 private key")
			}
			// We need to convert ecdsa.PrivateKey back to sm2.PrivateKey
			// Create a new sm2.PrivateKey and copy the ecdsa.PrivateKey data
			s.prk = &sm2.PrivateKey{
				PrivateKey: *ecdsaKey,
			}
		}
	} else if cfg.PrivateKey != "" {
		if err := s.WithPrivateKey(cfg.PrivateKey); err != nil {
			return nil, err
		}
	}

	if cfg.PublicKeyObject != nil {
		// SM2 uses ecdsa.PublicKey internally
		ecdsaKey, ok := cfg.PublicKeyObject.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("not an SM2 public key")
		}
		// Check if it's actually an SM2 key
		if !sm2.IsSM2PublicKey(ecdsaKey) {
			return nil, errors.New("not an SM2 public key")
		}
		s.puk = ecdsaKey
	} else if cfg.PublicKey != "" {
		if err := s.WithPublicKey(cfg.PublicKey); err != nil {
			return nil, err
		}
	}

	return s, nil
}

func (s *sm2_algo) Name() string {
	return "SM2"
}

func (s *sm2_algo) GenerateKey() (rootcrypto.KeyPair, error) {
	prv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return rootcrypto.KeyPair{}, err
	}

	s.prk = prv
	s.puk = &s.prk.PublicKey

	return rootcrypto.KeyPair{
		PrivateKey: prv,
		PublicKey:  &prv.PublicKey,
	}, nil
}

func (s *sm2_algo) WithPrivateKey(key string) error {
	der, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return err
	}

	parsed, err := smx509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return err
	}

	var ok bool
	s.prk, ok = parsed.(*sm2.PrivateKey)
	if !ok {
		return errors.New("failed to assert SM2 private key type")
	}

	return nil
}

func (s *sm2_algo) WithPublicKey(key string) error {
	der, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return err
	}

	parsed, err := smx509.ParsePKIXPublicKey(der)
	if err != nil {
		return err
	}

	var ok bool
	s.puk, ok = parsed.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("failed to assert ECDSA public key type")
	}
	// 拒绝普通 NIST P256 公钥：SM2 使用专属曲线，
	// 与对象注入路径（newSM2 中 IsSM2PublicKey 检查）语义对齐。
	if !sm2.IsSM2PublicKey(s.puk) {
		return errors.New("not an SM2 public key")
	}

	return nil
}

// 导出公钥所对应的公钥
func (s *sm2_algo) ExportPublicKey() (string, error) {
	if s.prk == nil {
		return "", errors.New("SM2 private key not set")
	}

	s.puk = &s.prk.PublicKey

	pubDER, err := smx509.MarshalPKIXPublicKey(s.puk)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(pubDER), nil
}

// Encrypt 使用 SM2 加密明文，返回 ASN.1 编码密文。
//
// 注意：gmsm 底层 Encrypt 对空明文（len(msg)==0）返回 (nil, nil)——
// 即不报错、也不产出任何密文。调用方若需拒绝空明文，应自行前置校验；
// 若按"空密文"处理，需自行区分 nil 密文与正常密文。
func (s *sm2_algo) Encrypt(msg []byte) (bytex.Bytes, error) {
	if s.puk == nil {
		return nil, errors.New("SM2 public key not set")
	}

	return sm2.EncryptASN1(rand.Reader, s.puk, msg)
}

func (s *sm2_algo) Decrypt(ciphertext []byte) (bytex.Bytes, error) {
	if s.prk == nil {
		return nil, errors.New("SM2 private key not set")
	}

	return s.prk.Decrypt(rand.Reader, ciphertext, nil)
}

func (s *sm2_algo) Sign(msg []byte) (bytex.Bytes, error) {
	if s.prk == nil {
		return nil, errors.New("SM2 private key not set")
	}
	// 校验私钥可用：KeyPair.Reset 清零后同指针实例可被检测到，
	// 避免对零值 D 静默产出无效签名。
	if s.prk.D == nil || s.prk.D.Sign() == 0 {
		return nil, errors.New("SM2 private key is invalid or has been reset")
	}

	return s.prk.SignWithSM2(rand.Reader, nil, msg)
}

func (s *sm2_algo) Verify(msg, sign []byte) bool {
	if s.puk == nil {
		return false
	}

	return sm2.VerifyASN1WithSM2(s.puk, nil, msg, sign)
}
