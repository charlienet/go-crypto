package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"math/big"

	"github.com/emmansun/gmsm/sm2"
)

// KeyGenConfig 密钥生成配置。构造期使用，选项仅应用一次，
// 构造完成后不再被读取，调用方不得跨构造复用。
type KeyGenConfig struct {
	KeySize int    // RSA 密钥位数（默认 2048）
	Curve   string // ECDSA 曲线名（默认 "P256"）
}

// KeyGenOption 密钥生成选项
type KeyGenOption func(*KeyGenConfig)

// WithKeySize 设置 RSA 密钥位数
func WithKeySize(bits int) KeyGenOption {
	return func(cfg *KeyGenConfig) {
		cfg.KeySize = bits
	}
}

// WithCurve 设置 ECDSA 曲线名称。
// 可用值：P-256 / P-384 / P-521（P-224 已被禁用，返回错误）。
// 默认值：P-256。
func WithCurve(curve string) KeyGenOption {
	return func(cfg *KeyGenConfig) {
		cfg.Curve = curve
	}
}

// KeyPair 存储底层密钥对象
//
// 并发安全说明：
// - 只读访问字段（PrivateKey/PublicKey）由调用方保证不并发写
// - Reset 修改字段，与读取不并发
//
// 序列化防护边界：json:"-" 仅对 encoding/json 生效（配合 MarshalJSON/UnmarshalJSON
// 禁止序列化）；gob/yaml 等其他序列化器仍会导出 PrivateKey/PublicKey 字段导致
// 私钥泄露。禁止经 gob/yaml 等序列化本类型。
//
// 编解码/文件读写/格式枚举已迁至 crypto/keymgr 子包的函数式 API
// （MarshalPublicKey/MarshalPrivateKey/Save*/Load*/Parse* 与 KeyFormat 等）。
type KeyPair struct {
	// json:"-" 防止值类型（不可寻址容器、map 值）绕过指针接收者 MarshalJSON
	// 后经 encoding/json 直接序列化导出字段导致私钥泄露。
	PrivateKey crypto.PrivateKey `json:"-"`
	PublicKey  crypto.PublicKey  `json:"-"`
}

// Reset 清除密钥并清零敏感内存
func (kp *KeyPair) Reset() {
	switch k := kp.PrivateKey.(type) {
	case *rsa.PrivateKey:
		if k != nil {
			b := k.D.Bits()
			for i := range b {
				b[i] = 0
			}
			for _, p := range k.Primes {
				pb := p.Bits()
				for i := range pb {
					pb[i] = 0
				}
			}
			// 清零预计算 CRT 参数，避免残留私钥派生数据
			// PrecomputedValues 为值类型，未 Precompute 时各 big.Int 字段为 nil
			for _, v := range []*big.Int{k.Precomputed.Dp, k.Precomputed.Dq, k.Precomputed.Qinv} {
				if v != nil {
					vb := v.Bits()
					for i := range vb {
						vb[i] = 0
					}
				}
			}
			for _, crt := range k.Precomputed.CRTValues {
				for _, v := range []*big.Int{crt.Exp, crt.Coeff, crt.R} {
					if v != nil {
						vb := v.Bits()
						for i := range vb {
							vb[i] = 0
						}
					}
				}
			}
		}
	case *ecdsa.PrivateKey:
		if k != nil {
			b := k.D.Bits()
			for i := range b {
				b[i] = 0
			}
		}
	case *sm2.PrivateKey:
		// sm2.PrivateKey 嵌入 ecdsa.PrivateKey（独立类型，不会命中上面的 case），
		// 需清零其嵌入私钥的 D 大数底层内存。
		if k != nil {
			b := k.D.Bits()
			for i := range b {
				b[i] = 0
			}
		}
	case ed25519.PrivateKey:
		// 清零底层字节。注意不对称性：清零后切片长度仍为 64，
		// 共享该切片的实例（如 NewAsymmetric 注入）Sign 无法经长度防线
		// 检测内容失效（Ed25519 无廉价一致性校验），
		// 调用方须避免复用已 Reset 的实例（详见 ed25519.go）。
		for i := range k {
			k[i] = 0
		}
	}
	kp.PrivateKey = nil
	kp.PublicKey = nil
}

// MarshalJSON 禁止序列化（防止私钥泄露）
func (kp *KeyPair) MarshalJSON() ([]byte, error) {
	return nil, errors.New("crypto: KeyPair JSON serialization is disabled to prevent private key leakage; use keymgr.MarshalPrivateKey for explicit encoding")
}

// UnmarshalJSON 禁止反序列化
func (kp *KeyPair) UnmarshalJSON(data []byte) error {
	return errors.New("crypto: KeyPair JSON deserialization is disabled; use keymgr.ParsePrivateKeyPair for explicit decoding")
}
