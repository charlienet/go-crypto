// Package agreement 提供密钥协商算法实现（ECDH/X25519/SM2）。
//
// 本包实现 crypto.KeyAgreement 接口，并在包初始化时经
// crypto.RegisterKeyAgreementFactory 将三个实现注册到根包注册表；
// 根包协议入口 NewKeyAgreement 经注册表分发到本包，因此使用前须
// blank import 本包（或经应用侧显式注册）：
//
//	import (
//		"github.com/charlienet/go-crypto"
//		_ "github.com/charlienet/go-crypto/agreement" // 注册协商引擎
//	)
//
//	ka, err := crypto.NewKeyAgreement(crypto.ECDH)
//	kp, err := ka.GenerateKey()
//	secret, err := ka.DeriveSharedSecret(peerPublicKey)
//
// 本包亦提供直接工厂 New：不经注册表、直发包内构造器。三预定义算法
// （ECDH/X25519/SM2）与根包 NewKeyAgreement 行为一致；子集外
// （RSA/ECDSA/ED25519）与非预定义值返回
// "unsupported key agreement algorithm: %s"：
//
//	ka, err := New(crypto.ECDH)
//	kp, err := ka.GenerateKey()
//	secret, err := ka.DeriveSharedSecret(peerPublicKey)
//
// 注意：SM2 协商的 DeriveSharedSecret 已被禁用（原实现为不安全的裸标量
// 乘法拼接 x||y，非标准 SM2 KAP——无前向保密、无 SM3-KDF、无密钥确认、
// 输出长度不稳定），详见 sm2.go 的说明。需要 SM2 曲线上的协商时请改用
// ECDH 或 X25519。
//
// 本包所有实现均非并发安全，每个实例应在单协程内使用。
package agreement
