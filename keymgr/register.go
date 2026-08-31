package keymgr

import "github.com/charlienet/go-crypto"

// init 将 RSA/ECDSA/ED25519/SM2 四个密钥对生成器注册到根包注册表，
// 使根包协议入口 GenerateKeyPair 可经注册表分发到本包。
// 键为 AsymmetricAlgorithm 常量的规范字符串形式。
// 注册失败属编程错误，直接 panic 暴露（对齐 symmetric/register.go 范式）。
func init() {
	if err := crypto.RegisterKeyPairGenerator(crypto.RSA.String(), generateRSA); err != nil {
		panic(err)
	}
	if err := crypto.RegisterKeyPairGenerator(crypto.ECDSA.String(), generateECDSA); err != nil {
		panic(err)
	}
	if err := crypto.RegisterKeyPairGenerator(crypto.ED25519.String(), generateED25519); err != nil {
		panic(err)
	}
	if err := crypto.RegisterKeyPairGenerator(crypto.SM2.String(), generateSM2); err != nil {
		panic(err)
	}
}
