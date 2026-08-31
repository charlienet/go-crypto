package agreement

import "github.com/charlienet/go-crypto"

// init 将 ECDH/X25519/SM2 三个密钥协商实现注册到根包注册表，
// 使根包协议入口 NewKeyAgreement 可经注册表分发到本包。
// 键为 AsymmetricAlgorithm 常量的规范字符串形式。
// 注册失败属编程错误，直接 panic 暴露（对齐 symmetric/register.go 范式）。
func init() {
	if err := crypto.RegisterKeyAgreementFactory(crypto.ECDH.String(), newECDH); err != nil {
		panic(err)
	}
	if err := crypto.RegisterKeyAgreementFactory(crypto.X25519.String(), newX25519); err != nil {
		panic(err)
	}
	if err := crypto.RegisterKeyAgreementFactory(crypto.SM2.String(), newSM2KeyAgreement); err != nil {
		panic(err)
	}
}
