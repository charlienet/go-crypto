package keymgr

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"

	"github.com/emmansun/gmsm/sm2"

	rootcrypto "github.com/charlienet/go-crypto"
)

// generateRSA 生成 RSA 密钥对。与加载路径（keycodec.go 的强度校验）对齐：
// 512/1024 位 RSA 已被视为可破解，生成侧同样拒绝弱位数。
func generateRSA(cfg *rootcrypto.KeyGenConfig) (*rootcrypto.KeyPair, error) {
	if cfg.KeySize < 2048 {
		return nil, fmt.Errorf("rsa key size must be at least 2048 bits, got %d", cfg.KeySize)
	}
	key, err := rsa.GenerateKey(rand.Reader, cfg.KeySize)
	if err != nil {
		return nil, err
	}
	return &rootcrypto.KeyPair{PrivateKey: key, PublicKey: &key.PublicKey}, nil
}

// generateSM2 生成 SM2 密钥对。
func generateSM2(cfg *rootcrypto.KeyGenConfig) (*rootcrypto.KeyPair, error) {
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &rootcrypto.KeyPair{PrivateKey: key, PublicKey: &key.PublicKey}, nil
}

// generateECDSA 生成 ECDSA 密钥对（曲线由 cfg.Curve 指定）。
func generateECDSA(cfg *rootcrypto.KeyGenConfig) (*rootcrypto.KeyPair, error) {
	curve, err := getCurve(cfg.Curve)
	if err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}
	return &rootcrypto.KeyPair{PrivateKey: key, PublicKey: &key.PublicKey}, nil
}

// generateED25519 生成 Ed25519 密钥对。
func generateED25519(cfg *rootcrypto.KeyGenConfig) (*rootcrypto.KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &rootcrypto.KeyPair{PrivateKey: priv, PublicKey: pub}, nil
}

// getCurve 返回指定名称的椭圆曲线。
// P224 已被移除（安全强度不足），返回明确错误。
func getCurve(name string) (elliptic.Curve, error) {
	switch name {
	case "P224":
		return nil, fmt.Errorf("curve P224 is not supported")
	case "P256":
		return elliptic.P256(), nil
	case "P384":
		return elliptic.P384(), nil
	case "P521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported curve: %s", name)
	}
}

// GenerateKeyPair 生成指定算法的密钥对（子包直接工厂）。
// 内部直发 RSA/ECDSA/ED25519/SM2 四个生成器；ECDH/X25519 属密钥协商，
// 非法值一律返回 unsupported algorithm 错误。
func GenerateKeyPair(algorithm rootcrypto.AsymmetricAlgorithm, opts ...rootcrypto.KeyGenOption) (*rootcrypto.KeyPair, error) {
	cfg := &rootcrypto.KeyGenConfig{KeySize: 2048, Curve: "P256"}
	for _, opt := range opts {
		opt(cfg)
	}
	switch algorithm {
	case rootcrypto.RSA:
		return generateRSA(cfg)
	case rootcrypto.SM2:
		return generateSM2(cfg)
	case rootcrypto.ECDSA:
		return generateECDSA(cfg)
	case rootcrypto.ED25519:
		return generateED25519(cfg)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

// LoadKeyPair 从文件加载密钥对：先按私钥解析（PEM 加密格式经密码解密），
// 失败后再按公钥解析。
func LoadKeyPair(filename string, format KeyFormat, opts ...LoadOption) (*rootcrypto.KeyPair, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return ParseKeyPair(data, format, opts...)
}

// LoadPrivateKeyPair 从文件加载私钥对（解析后自动提取公钥）。
func LoadPrivateKeyPair(filename string, format KeyFormat, opts ...LoadOption) (*rootcrypto.KeyPair, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return ParsePrivateKeyPair(data, format, opts...)
}

// LoadPublicKeyPair 从文件加载公钥。
func LoadPublicKeyPair(filename string, format KeyFormat) (*rootcrypto.KeyPair, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return ParsePublicKeyPair(data, format)
}

// ParseKeyPair 解析密钥数据：先按私钥解析，失败后再按公钥解析。
func ParseKeyPair(data []byte, format KeyFormat, opts ...LoadOption) (*rootcrypto.KeyPair, error) {
	kp, err := ParsePrivateKeyPair(data, format, opts...)
	if err == nil {
		return kp, nil
	}
	return ParsePublicKeyPair(data, format)
}

// ParsePrivateKeyPair 解析私钥数据（PEM 加密格式经 PBES2/传统格式解密），
// 返回的密钥对自动提取公钥。
func ParsePrivateKeyPair(data []byte, format KeyFormat, opts ...LoadOption) (*rootcrypto.KeyPair, error) {
	cfg := &loadConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	key, err := unmarshalPrivateKeyWithPassword(data, format, cfg)
	if err != nil {
		return nil, err
	}
	return &rootcrypto.KeyPair{PrivateKey: key, PublicKey: extractPublicKey(key)}, nil
}

// ParsePublicKeyPair 解析公钥数据。
func ParsePublicKeyPair(data []byte, format KeyFormat) (*rootcrypto.KeyPair, error) {
	key, err := unmarshalPublicKey(data, format)
	if err != nil {
		return nil, err
	}
	return &rootcrypto.KeyPair{PublicKey: key}, nil
}
