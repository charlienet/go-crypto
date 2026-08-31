package agreement

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"

	rootcrypto "github.com/charlienet/go-crypto"
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

// WithPrivateKey 注入既有私钥，支持两种类型（均须为与协商器匹配的
// P-256 曲线，当前 newECDH 固定 P-256）：
//   - *ecdh.PrivateKey：与 GenerateKey 内部生成类型一致，直接校验曲线并采用；
//   - *ecdsa.PrivateKey：存量密钥（如 keymgr 解析 NIST 曲线 PKCS#8 回读类型），
//     校验曲线后经标准库 key.ECDH() 转换（go1.24+）为 ecdh.PrivateKey。
func (k *ecdhKA) WithPrivateKey(key crypto.PrivateKey) error {
	switch priv := key.(type) {
	case *ecdh.PrivateKey:
		// 校验确为 P-256 曲线（曲线对象身份比较，区分 X25519 与其他 NIST 曲线）
		if priv.Curve() != ecdh.P256() {
			return fmt.Errorf("invalid private key curve for ECDH: %s (want P-256)", priv.Curve())
		}
		k.privateKey = priv
		return nil
	case *ecdsa.PrivateKey:
		// 校验曲线与协商器配置一致（当前固定 P-256）。
		// 使用曲线对象身份比较（elliptic.P256() 为包级单例），
		// 避免仅凭 Params().Name 字符串被伪造 Name 的自定义曲线绕过。
		if priv.Curve != elliptic.P256() {
			return fmt.Errorf("invalid ECDSA curve for ECDH: %s (want P-256)", priv.Curve.Params().Name)
		}
		// go1.24+ 标准库直接由 ECDSA 私钥转换标量，取代手工 FillBytes 拷贝路径
		ecdhKey, err := priv.ECDH()
		if err != nil {
			return fmt.Errorf("invalid ECDSA private key for ECDH: %w", err)
		}
		k.privateKey = ecdhKey
		return nil
	default:
		return fmt.Errorf("invalid private key type for ECDH: %T (want *ecdh.PrivateKey or *ecdsa.PrivateKey)", key)
	}
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
// peer 支持 *ecdh.PublicKey 与 *ecdsa.PublicKey（存量公钥，经标准库
// key.ECDH() 转换，go1.24+）；曲线不匹配由标准库 ECDH() 校验拒绝。
func (k *ecdhKA) DeriveSharedSecret(peerPublicKey crypto.PublicKey) ([]byte, error) {
	if k.privateKey == nil {
		return nil, errors.New("private key not set")
	}

	ecdhPub, ok := peerPublicKey.(*ecdh.PublicKey)
	if !ok {
		// *ecdsa.PublicKey（NIST 曲线 PKCS#8/SPKI 回读类型）走标准库转换
		ecdsaPub, ok2 := peerPublicKey.(*ecdsa.PublicKey)
		if !ok2 {
			return nil, errors.New("invalid public key type for ECDH")
		}
		var err error
		ecdhPub, err = ecdsaPub.ECDH()
		if err != nil {
			return nil, fmt.Errorf("invalid ECDSA public key for ECDH: %w", err)
		}
	}

	return k.privateKey.ECDH(ecdhPub)
}
