package symmetric

import "github.com/charlienet/go-crypto"

// init 注册对称引擎（blank import 本包时触发）：
// 6 个 CipherFactory（算法键自 cipher.go 的 supported 表派生，规范名；
// 泛名 "AES" 不再注册，经根包 NormalizeAlgorithm 归一落 "AES-128"）+
// 6 个 ModeExecutor（crypto.GCM/CBC/ECB/CFB/OFB/CTR）。
// 注册失败（键重复 / 引擎为 nil）属编程错误，直接 panic 暴露。
//
// 工厂闭包走 newBlockCipher（跳过不安全闸门）：DES/3DES 的闸门由根包
// NewCipher 基于 CipherFactory.Insecure 元数据检查后透传放行，此处不重复检查。
func init() {
	for name, c := range supported {
		if err := crypto.RegisterCipherFactory(name, crypto.CipherFactory{
			New: func(key []byte) (crypto.Cipher, error) {
				return newBlockCipher(name, key)
			},
			KeySize:  c.keySize,
			IVSize:   c.ivSize,
			Insecure: c.insecure,
		}); err != nil {
			panic(err)
		}
	}

	for mode, ex := range modeExecutors {
		if err := crypto.RegisterModeExecutor(mode, ex); err != nil {
			panic(err)
		}
	}
}
