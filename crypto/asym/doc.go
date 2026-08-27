// Package asym 非对称算法实现子包：RSA/ECDSA/Ed25519/SM2 四类非对称
// 加解密与签名验签算法，全部实现根包 crypto.Asymmetric 接口。
//
// # 注册约定
//
// 本包在 init() 中经 crypto.RegisterAsymmetricFactory 注册四类算法引擎
// （database/sql driver 模式，键为 AsymmetricAlgorithm.String() 规范名）。
// 注册后根包协议入口 crypto.NewAsymmetric 即可用；未导入本包时，调用方
// 收到 "no engine registered; import crypto/asym" 错误提示。
//
// blank import 即可完成注册：
//
//	import _ "github.com/charlienet/go-crypto/crypto/asym"
//
// 或直接依赖根包入口（本包 init 已随依赖生效）：
//
//	algo, err := crypto.NewAsymmetric(crypto.RSA, crypto.WithPrivateKeyObject(priv))
//
// # 直接工厂
//
// 本包提供直接工厂 New：不经注册表、直发包内构造器。四预定义算法
// （RSA/ECDSA/ED25519/SM2）与根包 NewAsymmetric 行为一致；子集外
// （ECDH/X25519）与非预定义值返回 "unsupported asymmetric algorithm: %s"：
//
//	a, err := New(crypto.SM2, crypto.WithPrivateKeyObject(priv))
//
// 根包入口 NewAsymmetric 经注册表分发到本包注册的同一引擎，构造行为与
// 直接工厂一致；未导入本包时提示 "no engine registered; import crypto/asym"。
// 本包各算法构造器签名与注册表工厂一致
// （func(...crypto.AsymOption) (crypto.Asymmetric, error)），
// 自定义引擎可参考其实现形态经 RegisterAsymmetricFactory 注入。
//
// # 密钥注入
//
// RSA/SM2 支持 base64 DER 字符串注入（crypto.WithPrivateKey/crypto.WithPublicKey），
// 亦支持密钥对象注入（crypto.WithPrivateKeyObject/crypto.WithPublicKeyObject）；
// ECDSA/Ed25519 仅支持密钥对象注入，字符串注入路径返回明确错误。
//
// 注意：本包只依赖根包契约类型与标准库/gmsm，不依赖其他算法子包；
// 依赖方向保持单向（子包 → 根包 → common）。
package asym
