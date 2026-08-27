package asym

import "github.com/charlienet/go-crypto"

// init 注册四类非对称算法引擎（database/sql driver 模式）。
// 键为 AsymmetricAlgorithm.String() 规范名（"RSA"/"ECDSA"/"ED25519"/"SM2"），
// 与注册表查询键约定一致；重复注册返回 ErrEngineExists 且不覆盖。
func init() {
	crypto.RegisterAsymmetricFactory(crypto.RSA.String(), newRSA)
	crypto.RegisterAsymmetricFactory(crypto.ECDSA.String(), newECDSA)
	crypto.RegisterAsymmetricFactory(crypto.ED25519.String(), newED25519)
	crypto.RegisterAsymmetricFactory(crypto.SM2.String(), newSM2)
}
