// Package symmetric 对称加密算法实现包（crypto 契约层的引擎子包）。
//
// 本包承载全部对称算法实现与六种工作模式执行器，经 crypto 根包注册表
// （registry.go）挂载：blank import 本包
// （import _ "github.com/charlienet/go-crypto/crypto/symmetric"）触发 init()
// 注册 7 个 CipherFactory（SM4/AES/AES-128/AES-192/AES-256/DES/3DES）与
// 6 个 ModeExecutor（ECB/CBC/CTR/CFB/OFB/GCM），此后根包协议入口
// （NewCipher/GenerateKey/BlockSize/Encrypt/Decrypt/NewEncryptor）即可用。
//
// 依赖方向保持单向：本包仅 import crypto 根包（接口/哨兵/选项/注册表），
// 根包永不反向依赖本包（database/sql driver 模式）。
//
// # 推荐用法
//
// 经根包协议入口（需 blank import 本包）：
//
//	ct, err := crypto.Encrypt(crypto.AES128, crypto.GCM, plaintext, crypto.WithKey(key))
//
// 可复用加密对象（构造一次，多次加解密，方法级并发安全）：
//
//	e, err := crypto.NewEncryptor(crypto.AES128, crypto.GCM, crypto.WithKey(key))
//	if err != nil {
//		return err
//	}
//	ct, err = e.Encrypt(plaintext)
//	pt, err = e.Decrypt(ct)
//
// 低层 API（NewCipher/NewGCM/NewCBC 等）签名与一次性语义与根包一致，
// 供需要直接控制 nonce/IV/填充的协议与遗留兼容场景使用。
package symmetric
