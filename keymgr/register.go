package keymgr

import "github.com/charlienet/go-crypto"

// init 将 RSA/ECDSA/ED25519/SM2 四个密钥对生成器注册到根包注册表，
// 使根包协议入口 GenerateKeyPair 可经注册表分发到本包。
// 键为 AsymmetricAlgorithm 常量的规范字符串形式。
func init() {
	crypto.RegisterKeyPairGenerator(crypto.RSA.String(), generateRSA)
	crypto.RegisterKeyPairGenerator(crypto.ECDSA.String(), generateECDSA)
	crypto.RegisterKeyPairGenerator(crypto.ED25519.String(), generateED25519)
	crypto.RegisterKeyPairGenerator(crypto.SM2.String(), generateSM2)
}
