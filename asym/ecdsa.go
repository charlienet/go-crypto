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

	"github.com/charlienet/go-utils/bytex"
	rootcrypto "github.com/charlienet/go-crypto"
)

type ecdsa_algo struct {
	prk  *ecdsa.PrivateKey
	puk  *ecdsa.PublicKey
	hash crypto.Hash
	// curve 签名/密钥生成使用的曲线（根包白名单 P256/P384/P521，默认 P256）。
	curve elliptic.Curve
}

// ecdsaSignature ASN.1 DER 编码的 ECDSA 签名结构（SEQUENCE { r, s INTEGER }）。
// 用于低 S 规范化时解析/重编码签名（本 Go 版本标准库未导出
// ecdsa.ParseSignature/EncodeSignature，改用 asn1 编解码等价实现）。
type ecdsaSignature struct {
	R, S *big.Int
}

// ecdsaCurveByName ECDSA 曲线白名单映射（规范名 → 曲线对象）。
// 曲线名由根包 WithECDSACurve 归一（"P256"/"P384"/"P521"），此处仅消费；
// 防御性兜底：直接构造 cfg 绕过选项层时返回错误。
var ecdsaCurveByName = map[string]elliptic.Curve{
	"P256": elliptic.P256(),
	"P384": elliptic.P384(),
	"P521": elliptic.P521(),
}

// newECDSA 构造 ECDSA 非对称算法实例（注册表工厂签名）。
func newECDSA(opts ...rootcrypto.AsymOption) (rootcrypto.Asymmetric, error) {
	cfg := &rootcrypto.AsymConfig{}
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, err
		}
	}

	algo := &ecdsa_algo{}

	// 消费 cfg.ECDSACurve（"" → 默认 P256）与 cfg.Hash（0 → 默认 SHA256）。
	if cfg.ECDSACurve != "" {
		curve, ok := ecdsaCurveByName[cfg.ECDSACurve]
		if !ok {
			return nil, fmt.Errorf("unsupported ECDSA curve %q (whitelist: P256/P384/P521)", cfg.ECDSACurve)
		}
		algo.curve = curve
	} else {
		algo.curve = elliptic.P256()
	}
	hash, err := asymHash(cfg.Hash)
	if err != nil {
		return nil, err
	}
	algo.hash = hash

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
		// 回填公钥：私钥注入后同实例可直接 Verify/Encrypt（公钥能力自动派生）。
		algo.puk = &ecdsaKey.PublicKey
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
	// 使用配置曲线（默认 P256；经 WithECDSACurve 可选用 P384/P521）
	key, err := ecdsa.GenerateKey(s.curve, rand.Reader)
	if err != nil {
		return rootcrypto.KeyPair{}, err
	}
	s.prk = key
	// 回填公钥：GenerateKey 后同实例可直接 Verify（公钥能力自动派生）。
	s.puk = &key.PublicKey
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

func (s *ecdsa_algo) Encrypt(msg []byte) (bytex.Bytes, error) {
	return nil, errors.New("ECDSA does not support encryption")
}

func (s *ecdsa_algo) Decrypt(ciphertext []byte) (bytex.Bytes, error) {
	return nil, errors.New("ECDSA does not support decryption")
}

func (s *ecdsa_algo) Sign(data []byte) (bytex.Bytes, error) {
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

	// 低 S 规范化（签名不可塑性，对齐比特币/以太坊/WebCrypto）：
	// ECDSA 签名中 (r, s) 与 (r, N-s) 数学上等价，均能通过验签；
	// 攻击者可将合法签名翻转为高 S 形态以规避签名归一/去重的黑名单
	// （如复用已被记录的 (r, s) 对）。这里强制 s ≤ N/2（halfOrder），
	// 输出唯一规范形态，并配合 Verify 拒绝高 S 签名。
	//
	// 注意：历史上由其他工具（如旧版 OpenSSL/OpenJDK 等未归一的实现）
	// 产生的高 S 签名在本库 Verify 将被拒绝——对接存量签名数据时
	// 需先做低 S 归一化或改用接受高 S 的实现。
	n := s.prk.Curve.Params().N
	halfOrder := new(big.Int).Rsh(new(big.Int).Set(n), 1)
	if s_val.Cmp(halfOrder) > 0 {
		s_val = new(big.Int).Sub(n, s_val)
	}

	// 返回 ASN.1 DER 编码的签名（低 S 规范化后重编码）
	return asn1.Marshal(ecdsaSignature{R: r, S: s_val})
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

	// 低 S 规则（与 Sign 对称）：先解析 DER 提取 s，s > N/2 的高 S 签名
	// 直接拒绝——与 Sign 只产出低 S 签名对应，保证签名形态唯一、
	// 不可被翻转重放（防止攻击者将合法签名 (r, s) 翻转为 (r, N-s)
	// 绕过基于签名值的黑名单/去重）。
	//
	// 注意：历史上由其他工具产生的高 S 签名在这里将被拒绝（false），
	// 与低 S 规范化的目的对齐（见 Sign 注释）。
	var parsed ecdsaSignature
	if _, err := asn1.Unmarshal(signature, &parsed); err != nil || parsed.R == nil || parsed.S == nil {
		return false
	}
	n := s.puk.Curve.Params().N
	halfOrder := new(big.Int).Rsh(new(big.Int).Set(n), 1)
	if parsed.S.Cmp(halfOrder) > 0 {
		return false
	}

	// 使用 ecdsa.VerifyASN1 严格完整消费 DER 签名：
	// 此前 asn1.Unmarshal 丢弃 rest，签名后追加垃圾字节仍会验签通过；
	// VerifyASN1 要求签名恰好为一个 DER 编码的 ECDSA 签名（无多余字节）。
	// 上面的低 S 检查仅提取 s，不修改签名，随后仍走完整 VerifyASN1。
	return ecdsa.VerifyASN1(s.puk, hashed, signature)
}
