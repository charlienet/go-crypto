package symmetric

import "github.com/charlienet/go-crypto/crypto"

// init 注册对称引擎（blank import 本包时触发）：
// 7 个 CipherFactory（算法键自 cipher.go 的 supported 表派生）+
// 6 个 ModeExecutor（crypto.GCM/CBC/ECB/CFB/OFB/CTR）。
// 注册失败（键重复 / 引擎为 nil）属编程错误，直接 panic 暴露。
func init() {
	for name, c := range supported {
		if err := crypto.RegisterCipherFactory(name, crypto.CipherFactory{
			New: func(key []byte) (crypto.Cipher, error) {
				return newCipher(name, key)
			},
			KeySize: c.keySize,
			IVSize:  c.ivSize,
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
