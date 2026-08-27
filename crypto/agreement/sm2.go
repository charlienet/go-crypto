package agreement

import (
	"crypto"
	"crypto/rand"
	"errors"

	"github.com/emmansun/gmsm/sm2"

	rootcrypto "github.com/charlienet/go-crypto/crypto"
)

// sm2KA SM2 密钥协商器。
//
// DeriveSharedSecret 已禁用：原实现为裸标量乘法（ScalarMult 拼接 x||y），
// 非标准 SM2 KAP（无前向保密、无 SM3-KDF、无密钥确认、输出长度不稳定），
// 继续提供会诱导误用，故返回明确错误。GenerateKey 保留（用于 SM2 密钥生成）。
type sm2KA struct {
	privateKey *sm2.PrivateKey
}

// errSM2KeyAgreementDisabled SM2 密钥协商被禁用的哨兵错误
var errSM2KeyAgreementDisabled = errors.New("sm2 key agreement: unsafe simplified derivation is disabled; use ECDH or X25519")

func newSM2KeyAgreement() (rootcrypto.KeyAgreement, error) {
	return &sm2KA{}, nil
}

func (k *sm2KA) Name() string {
	return "SM2"
}

// WithPrivateKey 不支持：SM2 密钥协商已禁用（见 errSM2KeyAgreementDisabled），
// 注入私钥无意义，返回明确错误，与 DeriveSharedSecret 语义保持一致。
func (k *sm2KA) WithPrivateKey(key crypto.PrivateKey) error {
	return errSM2KeyAgreementDisabled
}

func (k *sm2KA) GenerateKey() (*rootcrypto.KeyPair, error) {
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	k.privateKey = priv
	return &rootcrypto.KeyPair{
		PrivateKey: priv,
		PublicKey:  &priv.PublicKey,
	}, nil
}

// DeriveSharedSecret 已禁用：直接返回明确错误，不再执行任何派生。
func (k *sm2KA) DeriveSharedSecret(peerPublicKey crypto.PublicKey) ([]byte, error) {
	return nil, errSM2KeyAgreementDisabled
}
