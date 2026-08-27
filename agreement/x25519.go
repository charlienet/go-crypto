package agreement

import (
	"crypto"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"

	rootcrypto "github.com/charlienet/go-crypto"
)

// x25519KA X25519 密钥协商器实现（基于 crypto/ecdh 的 X25519 曲线）。
type x25519KA struct {
	privateKey *ecdh.PrivateKey
}

// newX25519 构造 X25519 协商器。
func newX25519() (rootcrypto.KeyAgreement, error) {
	return &x25519KA{}, nil
}

func (k *x25519KA) Name() string {
	return "X25519"
}

// WithPrivateKey 注入既有 X25519 私钥（*ecdh.PrivateKey，
// 与 GenerateKey 内部使用的 ecdh.X25519() 生成类型一致）。
func (k *x25519KA) WithPrivateKey(key crypto.PrivateKey) error {
	priv, ok := key.(*ecdh.PrivateKey)
	if !ok {
		return fmt.Errorf("invalid private key type for X25519: %T (want *ecdh.PrivateKey)", key)
	}
	// 校验确为 X25519 私钥（区分 NIST 曲线 ecdh 私钥）
	if priv.Curve() != ecdh.X25519() {
		return errors.New("invalid private key for X25519: curve mismatch")
	}
	k.privateKey = priv
	return nil
}

func (k *x25519KA) GenerateKey() (*rootcrypto.KeyPair, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	k.privateKey = priv
	return &rootcrypto.KeyPair{
		PrivateKey: priv,
		PublicKey:  priv.PublicKey(),
	}, nil
}

// DeriveSharedSecret 返回 X25519 原始共享密钥（未派生）。使用前必须经
// HKDF 等 KDF 处理，且对端公钥必须来自认证通道。
func (k *x25519KA) DeriveSharedSecret(peerPublicKey crypto.PublicKey) ([]byte, error) {
	if k.privateKey == nil {
		return nil, errors.New("private key not set")
	}

	ecdhPub, ok := peerPublicKey.(*ecdh.PublicKey)
	if !ok {
		return nil, errors.New("invalid public key type for X25519")
	}

	return k.privateKey.ECDH(ecdhPub)
}
