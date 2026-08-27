package agreement

import "github.com/charlienet/go-crypto/crypto"

// init 将 ECDH/X25519/SM2 三个密钥协商实现注册到根包注册表，
// 使根包协议入口 NewKeyAgreement 可经注册表分发到本包。
// 键为 AsymmetricAlgorithm 常量的规范字符串形式。
func init() {
	crypto.RegisterKeyAgreementFactory(crypto.ECDH.String(), newECDH)
	crypto.RegisterKeyAgreementFactory(crypto.X25519.String(), newX25519)
	crypto.RegisterKeyAgreementFactory(crypto.SM2.String(), newSM2KeyAgreement)
}
