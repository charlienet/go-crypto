package agreement

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"

	rootcrypto "github.com/charlienet/go-crypto/crypto"
)

// ecdhKA ECDH 密钥协商器实现（基于 crypto/ecdh，固定 P-256 曲线）。
type ecdhKA struct {
	privateKey *ecdh.PrivateKey
	curve      ecdh.Curve
}

// newECDH 构造 ECDH 协商器（P-256）。
func newECDH() (rootcrypto.KeyAgreement, error) {
	return &ecdhKA{curve: ecdh.P256()}, nil
}

func (k *ecdhKA) Name() string {
	return "ECDH"
}

// WithPrivateKey 注入既有 ECDSA 私钥（须为与协商器匹配曲线的 *ecdsa.PrivateKey，
// 当前 newECDH 固定 P-256），与 GenerateKey 生成曲线保持一致。
func (k *ecdhKA) WithPrivateKey(key crypto.PrivateKey) error {
	ecdsaKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return fmt.Errorf("invalid private key type for ECDH: %T (want *ecdsa.PrivateKey)", key)
	}
	// 校验曲线与协商器配置一致（当前固定 P-256）。
	// 使用曲线对象身份比较（elliptic.P256() 为包级单例），
	// 避免仅凭 Params().Name 字符串被伪造 Name 的自定义曲线绕过。
	if ecdsaKey.Curve != elliptic.P256() {
		return fmt.Errorf("invalid ECDSA curve for ECDH: %s (want P-256)", ecdsaKey.Curve.Params().Name)
	}
	// 将 ECDSA 私钥标量转换为 ecdh.PrivateKey（与 GenerateKey 内部类型一致）
	d := make([]byte, 32)
	ecdsaKey.D.FillBytes(d)
	defer func() {
		for i := range d {
			d[i] = 0
		}
	}()
	priv, err := ecdh.P256().NewPrivateKey(d)
	if err != nil {
		return fmt.Errorf("invalid ECDSA private key for ECDH: %w", err)
	}
	k.privateKey = priv
	return nil
}

func (k *ecdhKA) GenerateKey() (*rootcrypto.KeyPair, error) {
	priv, err := k.curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	k.privateKey = priv
	return &rootcrypto.KeyPair{
		PrivateKey: priv,
		PublicKey:  priv.PublicKey(),
	}, nil
}

// DeriveSharedSecret 返回 ECDH 原始共享密钥（未派生）。使用前必须经
// HKDF 等 KDF 处理，且对端公钥必须来自认证通道。
func (k *ecdhKA) DeriveSharedSecret(peerPublicKey crypto.PublicKey) ([]byte, error) {
	if k.privateKey == nil {
		return nil, errors.New("private key not set")
	}

	ecdhPub, ok := peerPublicKey.(*ecdh.PublicKey)
	if !ok {
		return nil, errors.New("invalid public key type for ECDH")
	}

	return k.privateKey.ECDH(ecdhPub)
}
