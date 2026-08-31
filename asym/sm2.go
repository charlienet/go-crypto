package asym

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/charlienet/go-utils/bytex"
	rootcrypto "github.com/charlienet/go-crypto"
	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

type sm2_algo struct {
	prk *sm2.PrivateKey
	puk *ecdsa.PublicKey
	// uid SM2 用户标识（cfg.SM2UID，nil → 传 nil 走 gmsm 默认 UID）。
	// Sign（经 NewSM2SignerOption）与 Verify（VerifyASN1WithSM2）必须同源，
	// 否则 ZA 计算不同导致验签失败。
	uid []byte
	// legacyCipher 使用 SM2 遗留非认证密文格式（C1C2C3 裸拼接，非 ASN.1）。
	// 默认 false：新认证格式（C1C3C2，ASN.1 编码）。仅对接 GM/T 0009-2012
	// 旧数据时启用。
	legacyCipher bool
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

	// 消费 SM2 专属选项：
	//   - cfg.SM2UID：nil → 传 nil 走 gmsm 默认 UID（"1234567812345678"）
	//   - cfg.SM2LegacyCipher：true → 遗留 C1C2C3 非认证密文格式
	//   - cfg.Hash：SM2 固定使用 SM3 摘要，不支持自定义签名摘要算法；
	//     显式传非 0 值（根包白名单已放行 SHA256/384/512）在此显式报错，
	//     与根包校验一致的 fail-fast 语义。
	s.uid = cfg.SM2UID
	s.legacyCipher = cfg.SM2LegacyCipher
	if cfg.Hash != 0 {
		return nil, fmt.Errorf("SM2 does not support custom asymmetric hash %v: SM2 signature uses SM3", cfg.Hash)
	}

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
			// 显式 IsOnCurve 校验（用 SM2 曲线对象的 IsOnCurve，非 elliptic 默认曲线）：
			// IsSM2PublicKey 只比对曲线对象身份，仍需拒绝"曲线对但点不在曲线上"
			// 的伪造私钥公钥点。
			if !ecdsaKey.IsOnCurve(ecdsaKey.X, ecdsaKey.Y) {
				return nil, errors.New("SM2 public key point is not on curve")
			}
			// We need to convert ecdsa.PrivateKey back to sm2.PrivateKey
			// Create a new sm2.PrivateKey and copy the ecdsa.PrivateKey data
			s.prk = &sm2.PrivateKey{
				PrivateKey: *ecdsaKey,
			}
		}
		// 回填公钥：私钥注入后同实例可直接 Verify/Encrypt（公钥能力自动派生）。
		s.puk = &s.prk.PublicKey
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
		// 显式 IsOnCurve 校验：拒绝曲线对但点不在曲线上的伪造公钥
		//（IsSM2PublicKey 仅比较曲线对象身份，不校验点的合法性）。
		if !ecdsaKey.IsOnCurve(ecdsaKey.X, ecdsaKey.Y) {
			return nil, errors.New("SM2 public key point is not on curve")
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
	// 回填公钥：私钥注入后同实例可直接 Verify/Encrypt（公钥能力自动派生）。
	s.puk = &s.prk.PublicKey

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
	// 显式 IsOnCurve 校验：拒绝曲线对但点不在曲线上的伪造公钥。
	if !s.puk.IsOnCurve(s.puk.X, s.puk.Y) {
		return errors.New("SM2 public key point is not on curve")
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

// Encrypt 使用 SM2 加密明文。
//
// 默认（SM2LegacyCipher=false）返回 ASN.1 编码的新认证密文格式
// （C1C3C2，密文携带 SM3 摘要可检测篡改）；启用 WithSM2LegacyCiphertext
// 后改为遗留非认证格式（C1C2C3 裸拼接、非 ASN.1，首字节 0x04 为未压缩
// 点前缀），仅用于对接 GM/T 0009-2012 旧数据——遗留格式无认证，
// 无法检测密文篡改，非存量对接场景请保持默认。
//
// 注意：底层 gmsm Encrypt 对空明文（len(msg)==0）返回 (nil, nil)——
// 不报错也不产出密文，调用方无从区分"加密成功但结果为空"与"失败"。
// 本方法前置拒绝空明文（len(msg)==0 返回明确错误）。
func (s *sm2_algo) Encrypt(msg []byte) (bytex.Bytes, error) {
	if s.puk == nil {
		return nil, errors.New("SM2 public key not set")
	}
	if len(msg) == 0 {
		return nil, errors.New("SM2 encrypt: empty plaintext")
	}

	if s.legacyCipher {
		// 遗留模式：C1C2C3 裸拼接（非 ASN.1），未压缩点编码（首字节 0x04）
		return sm2.Encrypt(rand.Reader, s.puk, msg, sm2.NewPlainEncrypterOpts(sm2.MarshalUncompressed, sm2.C1C2C3))
	}
	return sm2.EncryptASN1(rand.Reader, s.puk, msg)
}

func (s *sm2_algo) Decrypt(ciphertext []byte) (bytex.Bytes, error) {
	if s.prk == nil {
		return nil, errors.New("SM2 private key not set")
	}

	if s.legacyCipher {
		// 遗留模式显式拒绝 ASN.1 前缀密文：gmsm 的 parseCiphertext 会自动
		// 识别并放行 ASN.1 编码（首字节 0x30），若不加判别本分支会静默
		// 解出新格式密文——破坏"两模式互解必须失败"的格式隔离语义，
		// 且遗留对接方不会产生 ASN.1 密文。
		if len(ciphertext) > 0 && ciphertext[0] == 0x30 {
			return nil, errors.New("SM2 legacy decrypt: ASN.1 ciphertext not supported in legacy mode")
		}
		return s.prk.Decrypt(rand.Reader, ciphertext, sm2.NewPlainDecrypterOpts(sm2.C1C2C3))
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

	// 经 NewSM2SignerOption(true, uid) 签名：uid 为 nil 时 gmsm 内部归一为
	// 默认 UID（"1234567812345678"）。与 deprecated 的 SignWithSM2 等价，
	// 但支持显式传自定义 UID（cfg.SM2UID）。
	return s.prk.Sign(rand.Reader, msg, sm2.NewSM2SignerOption(true, s.uid))
}

func (s *sm2_algo) Verify(msg, sign []byte) bool {
	if s.puk == nil {
		return false
	}

	// 与 Sign 同一 uid 源：若 Sign 用自定义 UID 而 Verify 用默认（nil），
	// ZA 摘要不同，验签必然失败——这正是 UID 语义要求的隔离行为。
	return sm2.VerifyASN1WithSM2(s.puk, s.uid, msg, sign)
}
