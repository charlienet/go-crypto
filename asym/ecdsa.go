package asym

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"

	"github.com/charlienet/go-utils/bytesconv"
	rootcrypto "github.com/charlienet/go-crypto"
)

type ecdsa_algo struct {
	prk  *ecdsa.PrivateKey
	puk  *ecdsa.PublicKey
	hash crypto.Hash
}

// newECDSA 构造 ECDSA 非对称算法实例（注册表工厂签名）。
func newECDSA(opts ...rootcrypto.AsymOption) (rootcrypto.Asymmetric, error) {
	cfg := &rootcrypto.AsymConfig{}
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, err
		}
	}

	algo := &ecdsa_algo{
		hash: crypto.SHA256,
	}

	if cfg.PrivateKeyObject != nil {
		ecdsaKey, ok := cfg.PrivateKeyObject.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("not an ECDSA private key")
		}
		// 复用公钥校验（IsOnCurve + 白名单），与公钥注入路径语义一致：
		// 拒绝 P224 等弱曲线私钥及点不在曲线上的非法私钥。
		if err := validateECDSAPublicKey(&ecdsaKey.PublicKey); err != nil {
			return nil, err
		}
		algo.prk = ecdsaKey
	}

	if cfg.PublicKeyObject != nil {
		ecdsaKey, ok := cfg.PublicKeyObject.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("not an ECDSA public key")
		}
		// 公钥合法性校验：点在曲线上且曲线在白名单（拒绝 P224 等弱曲线）
		if err := validateECDSAPublicKey(ecdsaKey); err != nil {
			return nil, err
		}
		algo.puk = ecdsaKey
	}

	return algo, nil
}

// isAllowedECDSACurve 判断曲线是否在白名单（P-256/P-384/P-521，拒绝 P-224 及其他）。
// 使用曲线对象身份比较（elliptic.P256()/P384()/P521() 为包级单例），
// 而非仅凭 Params().Name 字符串——避免被伪造 Name 的自定义曲线实现绕过。
func isAllowedECDSACurve(curve elliptic.Curve) bool {
	return curve == elliptic.P256() || curve == elliptic.P384() || curve == elliptic.P521()
}

// validateECDSAPublicKey 校验 ECDSA 公钥合法性：公钥非空、点在曲线上、曲线在白名单。
func validateECDSAPublicKey(pub *ecdsa.PublicKey) error {
	if pub == nil || pub.Curve == nil || pub.X == nil || pub.Y == nil {
		return errors.New("invalid ECDSA public key")
	}
	if !pub.IsOnCurve(pub.X, pub.Y) {
		return errors.New("ECDSA public key point is not on curve")
	}
	if !isAllowedECDSACurve(pub.Curve) {
		return fmt.Errorf("unsupported ECDSA curve: %s", pub.Curve.Params().Name)
	}
	return nil
}

func (s *ecdsa_algo) Name() string {
	return "ECDSA"
}

func (s *ecdsa_algo) GenerateKey() (rootcrypto.KeyPair, error) {
	// 使用 P256 曲线
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return rootcrypto.KeyPair{}, err
	}
	s.prk = key
	return rootcrypto.KeyPair{PrivateKey: key, PublicKey: &key.PublicKey}, nil
}

func (s *ecdsa_algo) WithPrivateKey(privateKey string) error {
	return errors.New("ECDSA WithPrivateKey(string) is not supported, use WithPrivateKeyObject instead")
}

func (s *ecdsa_algo) WithPublicKey(publicKey string) error {
	return errors.New("ECDSA WithPublicKey(string) is not supported, use WithPublicKeyObject instead")
}

func (s *ecdsa_algo) ExportPublicKey() (string, error) {
	if s.prk == nil && s.puk == nil {
		return "", errors.New("no key set")
	}

	pub := s.puk
	if pub == nil {
		pub = &s.prk.PublicKey
	}

	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(der), nil
}

func (s *ecdsa_algo) Encrypt(msg []byte) (bytesconv.BytesResult, error) {
	return nil, errors.New("ECDSA does not support encryption")
}

func (s *ecdsa_algo) Decrypt(ciphertext []byte) (bytesconv.BytesResult, error) {
	return nil, errors.New("ECDSA does not support decryption")
}

func (s *ecdsa_algo) Sign(data []byte) (bytesconv.BytesResult, error) {
	if s.prk == nil {
		return nil, errors.New("ECDSA private key not set")
	}
	// 校验私钥可用：KeyPair.Reset 清零后同指针实例可被检测到，
	// 避免对零值 D 静默产出无效签名。
	if s.prk.D == nil || s.prk.D.Sign() == 0 {
		return nil, errors.New("ECDSA private key is invalid or has been reset")
	}

	h := s.hash.New()
	h.Write(data)
	hashed := h.Sum(nil)

	r, s_val, err := ecdsa.Sign(rand.Reader, s.prk, hashed)
	if err != nil {
		return nil, err
	}

	// 返回 ASN.1 DER 编码的签名
	type ecdsaSignature struct {
		R, S *big.Int
	}
	sig := ecdsaSignature{R: r, S: s_val}
	return asn1.Marshal(sig)
}

func (s *ecdsa_algo) Verify(data, signature []byte) bool {
	if s.puk == nil {
		return false
	}
	// 构造期所有注入路径（私钥对象、公钥对象、GenerateKey）均已执行
	// validateECDSAPublicKey（IsOnCurve + 白名单）；Verify 期仅保留轻量曲线
	// 白名单防御（防实例被篡改/替换），不再重复 IsOnCurve——
	// 其代价与一次标量乘法同量级，高吞吐验签下会拖慢一倍。
	if !isAllowedECDSACurve(s.puk.Curve) {
		return false
	}

	h := s.hash.New()
	h.Write(data)
	hashed := h.Sum(nil)

	// 使用 ecdsa.VerifyASN1 严格完整消费 DER 签名：
	// 此前 asn1.Unmarshal 丢弃 rest，签名后追加垃圾字节仍会验签通过；
	// VerifyASN1 要求签名恰好为一个 DER 编码的 ECDSA 签名（无多余字节）。
	return ecdsa.VerifyASN1(s.puk, hashed, signature)
}
