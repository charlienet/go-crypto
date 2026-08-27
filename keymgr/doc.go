// Package keymgr 提供密钥管理能力：密钥对生成、编解码、文件读写
// 与 PBES2 私钥加密，全部以函数式 API 提供。
//
// 本包在包初始化时经 crypto.RegisterKeyPairGenerator 将 RSA/ECDSA/
// ED25519/SM2 四个生成器注册到根包注册表；根包协议入口
// GenerateKeyPair 经注册表分发到本包，因此使用前须 blank import
// 本包（或经应用侧显式注册）：
//
//	import (
//		"github.com/charlienet/go-crypto"
//		_ "github.com/charlienet/go-crypto/keymgr" // 注册密钥对生成器
//	)
//
//	kp, err := crypto.GenerateKeyPair(crypto.RSA, crypto.WithKeySize(4096))
//
// 也可直接使用本包函数式 API（不经注册表，内部直发各生成器）：
//
//	kp, err := keymgr.GenerateKeyPair(crypto.RSA, crypto.WithKeySize(4096))
//	der, err := keymgr.MarshalPrivateKey(kp.PrivateKey, keymgr.KeyFormatPEM,
//		keymgr.WithEncryptionPassword(password))
//	loaded, err := keymgr.ParsePrivateKeyPair(der, keymgr.KeyFormatPEM,
//		keymgr.WithPassword(password))
//
// 密钥格式：KeyFormatBase64（默认，Base64 编码的 DER）、KeyFormatPEM、
// KeyFormatHex、KeyFormatRaw。PEM 私钥加密使用 PBES2
// （PBKDF2-HMAC-SHA256 + AES-256-CBC，RFC 8018），取代已弃用的
// x509.EncryptPEMBlock 传统格式；传统加密 PEM 仅保留读取兼容。
//
// RSA 密钥默认使用 PKCS8 格式（WithRSAKeyFormat 默认值）。
// 如需 PKCS1 格式，显式传入 WithRSAKeyFormat(RSAKeyFormatPKCS1)。
//
// 安全说明：解析出的私钥与中间 DER 缓冲在生命周期内原地清零；
// 私钥文件写入权限为 0600，公钥为 0644。
package keymgr
