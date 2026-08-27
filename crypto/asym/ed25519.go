package asym

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/charlienet/go-utils/bytesconv"
	rootcrypto "github.com/charlienet/go-crypto/crypto"
)

type ed25519_algo struct {
	prk ed25519.PrivateKey
	puk ed25519.PublicKey
}

// newED25519 构造 Ed25519 非对称算法实例（注册表工厂签名）。
func newED25519(opts ...rootcrypto.AsymOption) (rootcrypto.Asymmetric, error) {
	cfg := &rootcrypto.AsymConfig{}
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, err
		}
	}

	algo := &ed25519_algo{}

	if cfg.PrivateKeyObject != nil {
		edKey, ok := cfg.PrivateKeyObject.(ed25519.PrivateKey)
		if !ok {
			return nil, errors.New("not an Ed25519 private key")
		}
		// 私钥长度必须恰为 ed25519.PrivateKeySize（64），
		// 否则标准库 ed25519.Sign 会 panic。
		if len(edKey) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("invalid Ed25519 private key length %d, want %d", len(edKey), ed25519.PrivateKeySize)
		}
		// 拷贝注入的切片：调用方后续修改原切片不应影响本实例持有的密钥
		algo.prk = append([]byte(nil), edKey...)
	}

	if cfg.PublicKeyObject != nil {
		edKey, ok := cfg.PublicKeyObject.(ed25519.PublicKey)
		if !ok {
			return nil, errors.New("not an Ed25519 public key")
		}
		// 拷贝注入的切片，避免与调用方共享底层数组
		algo.puk = append([]byte(nil), edKey...)
	}

	return algo, nil
}

// Name 返回算法名。历史行为保留："Ed25519"（与注册表键 "ED25519" 大小写不同，
// 注册表键使用 AsymmetricAlgorithm.String() 的规范形式，Name() 保持既有输出）。
func (s *ed25519_algo) Name() string {
	return "Ed25519"
}

func (s *ed25519_algo) GenerateKey() (rootcrypto.KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return rootcrypto.KeyPair{}, err
	}
	s.prk = priv
	s.puk = pub
	return rootcrypto.KeyPair{PrivateKey: priv, PublicKey: pub}, nil
}

func (s *ed25519_algo) WithPrivateKey(privateKey string) error {
	return errors.New("Ed25519 WithPrivateKey(string) is not supported, use WithPrivateKeyObject instead")
}

func (s *ed25519_algo) WithPublicKey(publicKey string) error {
	return errors.New("Ed25519 WithPublicKey(string) is not supported, use WithPublicKeyObject instead")
}

func (s *ed25519_algo) ExportPublicKey() (string, error) {
	if s.prk == nil && s.puk == nil {
		return "", errors.New("no key set")
	}

	pub := s.puk
	if pub == nil {
		pub = s.prk.Public().(ed25519.PublicKey)
	}

	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(der), nil
}

func (s *ed25519_algo) Encrypt(msg []byte) (bytesconv.BytesResult, error) {
	return nil, errors.New("Ed25519 does not support encryption")
}

func (s *ed25519_algo) Decrypt(ciphertext []byte) (bytesconv.BytesResult, error) {
	return nil, errors.New("Ed25519 does not support decryption")
}

func (s *ed25519_algo) Sign(data []byte) (bytesconv.BytesResult, error) {
	if s.prk == nil {
		return nil, errors.New("Ed25519 private key not set")
	}
	// 防御性校验私钥长度：KeyPair.Reset 清零后切片仍在但内容失效，
	// 长度防线同时覆盖注入路径与清零场景，避免标准库 Sign panic。
	// 注意与 RSA/ECDSA/SM2 的不对称：Ed25519 全零私钥长度仍为 64，
	// 无廉价一致性校验（RSA Validate / ECDSA/SM2 D 零值）可检测内容清零，
	// Reset 后共享本实例的调用方 Sign 仍会产出无效签名——
	// 调用方须避免复用已 Reset 的实例。
	if len(s.prk) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid Ed25519 private key length %d, want %d", len(s.prk), ed25519.PrivateKeySize)
	}

	signature := ed25519.Sign(s.prk, data)
	return signature, nil
}

func (s *ed25519_algo) Verify(data, signature []byte) bool {
	if s.puk == nil {
		return false
	}

	return ed25519.Verify(s.puk, data, signature)
}
