package asym

import "github.com/charlienet/go-crypto"

// init 注册四类非对称算法引擎（database/sql driver 模式）。
// 键为 AsymmetricAlgorithm.String() 规范名（"RSA"/"ECDSA"/"ED25519"/"SM2"），
// 与注册表查询键约定一致；重复注册返回 ErrEngineExists 且不覆盖。
// 注册失败属编程错误，直接 panic 暴露（对齐 symmetric/register.go 范式）。
func init() {
	if err := crypto.RegisterAsymmetricFactory(crypto.RSA.String(), newRSA); err != nil {
		panic(err)
	}
	if err := crypto.RegisterAsymmetricFactory(crypto.ECDSA.String(), newECDSA); err != nil {
		panic(err)
	}
	if err := crypto.RegisterAsymmetricFactory(crypto.ED25519.String(), newED25519); err != nil {
		panic(err)
	}
	if err := crypto.RegisterAsymmetricFactory(crypto.SM2.String(), newSM2); err != nil {
		panic(err)
	}
}
