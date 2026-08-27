package crypto

// AsymmetricAlgorithm 公钥算法枚举：覆盖非对称加解密/签名（RSA/ECDSA/Ed25519/SM2）
// 与密钥协商（ECDH/X25519/SM2）。
//
// 底层类型为 string 而非 uint8：库预定义六个常量（见下），同时支持第三方算法扩展——
// 经 Register*Factory 注册的自定义算法可用类型转换选中，例如 AsymmetricAlgorithm("ML-KEM")。
// 三个入口对预定义常量做合法子集校验：
//
//	NewAsymmetric：RSA/ECDSA/ED25519/SM2
//	NewKeyAgreement：ECDH/X25519/SM2
//	GenerateKeyPair：RSA/ECDSA/ED25519/SM2
//
// 非预定义值（含自定义算法名）一律直接查询注册表，未注册时报 "no engine registered; import ..." 错误。
type AsymmetricAlgorithm string

const (
	RSA     AsymmetricAlgorithm = AlgorithmRSA
	ECDSA   AsymmetricAlgorithm = AlgorithmECDSA
	ED25519 AsymmetricAlgorithm = AlgorithmED25519
	SM2     AsymmetricAlgorithm = AlgorithmSM2
	ECDH    AsymmetricAlgorithm = AlgorithmECDH
	X25519  AsymmetricAlgorithm = AlgorithmX25519
)

// String 返回算法名字符串（预定义常量输出与 NormalizeAlgorithm 规范形式一致；自定义值原样返回）。
func (a AsymmetricAlgorithm) String() string { return string(a) }

// IsPredefined 报告算法是否为库预定义常量之一（诊断/测试用，入口校验不依赖本方法）。
func (a AsymmetricAlgorithm) IsPredefined() bool {
	switch a {
	case RSA, ECDSA, ED25519, SM2, ECDH, X25519:
		return true
	}
	return false
}

// ParseAsymmetricAlgorithm 将算法名转换为枚举值：预定义算法大小写不敏感（经 NormalizeAlgorithm
// 归一化）；非预定义名称原样返回、不做归一化，交由入口查询注册表。不校验可用性（无 error 返回），
// 校验职责统一由入口承担。ParseAsymmetricAlgorithm(a.String()) == a 对任意值成立。
func ParseAsymmetricAlgorithm(s string) AsymmetricAlgorithm {
	if normalized, err := NormalizeAlgorithm(s); err == nil {
		switch AsymmetricAlgorithm(normalized) {
		case RSA, ECDSA, ED25519, SM2, ECDH, X25519:
			return AsymmetricAlgorithm(normalized)
		}
	}
	return AsymmetricAlgorithm(s)
}
