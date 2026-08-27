// Package crypto 是 go-misc 的加密契约层：定义接口、枚举、选项契约、错误
// 哨兵、引擎注册表与协议层入口。全部算法实现位于子包
// （symmetric/asym/agreement/keymgr），经注册表挂载（database/sql
// driver 模式）；依赖方向保持单向（子包 → 本包 → common），本包永不
// import 子包。
//
// # 契约面
//
//   - 接口：Cipher/CipherMode/StreamCipher/Padding（对称）、Asymmetric/
//     Signer（非对称）、KeyAgreement（密钥协商）；
//   - 枚举：Algorithm（对称算法，uint8 封闭）、Mode（工作模式）、
//     AsymmetricAlgorithm（公钥算法，string 底层、开放扩展）；
//   - 选项契约：Option/Config（对称）、AsymOption/AsymConfig（非对称）、
//     KeyGenOption/KeyGenConfig（密钥生成），以及 ApplyOptions；
//   - 错误哨兵：ErrUnknownAlgorithm/ErrKeyRequired/ErrInvalidKeyLength/
//     ErrAuthenticationFailed/ErrInvalidPadding/ErrEngineNotRegistered 等，
//     均支持 errors.Is 判定；
//   - 注册表：RegisterCipherFactory/RegisterModeExecutor/RegisterAsymmetricFactory/
//     RegisterKeyAgreementFactory/RegisterKeyPairGenerator 与对应查询函数；
//   - 协议层入口：Encrypt/Decrypt/NewEncryptor（对称）、NewAsymmetric
//     （非对称）、NewKeyAgreement（密钥协商）、GenerateKeyPair（密钥生成）、
//     NewCipher/GenerateKey/BlockSize（低层分发）。
//
// # 双轨 API
//
// 同一算法能力提供两条轨道，底层为同一实现、输出互解：
//
//   - 根包协议入口（推荐）：经注册表分发到子包实现，签名统一、错误语义
//     集中。使用前须 blank import 对应引擎子包（见下）。
//   - 子包直接工厂：不经注册表、直发实现。symmetric.New 返回与根包
//     NewEncryptor 同一对象类型（*crypto.Encryptor）；keymgr 提供
//     GenerateKeyPair/MarshalPrivateKey 等函数式 API（编解码/落盘/格式
//     枚举）；asym.New 与 agreement.New 分别对应根包 NewAsymmetric/
//     NewKeyAgreement 的预定义子集（直发包内构造器，行为一致）。
//
// 选择建议：进程内加解密优先根包协议入口；需要密钥编解码/文件读写时直接
// 使用 keymgr 函数式 API；需要低层精确控制 nonce/IV/填充的协议与遗留兼容
// 场景使用 NewCipher/NewGCM/NewCBC 等低层构造。
//
// # 注册表与 blank import 约定
//
// 各引擎子包在 init() 中注册自身实现；注册表永不覆盖已占用键（重复注册
// 返回 ErrEngineExists）。使用协议入口前须导入对应子包：
//
//	import _ "github.com/charlienet/go-crypto/crypto/symmetric" // 对称算法+模式
//	import _ "github.com/charlienet/go-crypto/crypto/asym"      // 非对称加解密/签名
//	import _ "github.com/charlienet/go-crypto/crypto/agreement" // 密钥协商
//	import _ "github.com/charlienet/go-crypto/crypto/keymgr"    // 密钥对生成
//
// 未导入对应子包时，协议入口返回形如
// "unsupported algorithm: AES-128 (no engine registered; import crypto/symmetric)"
// 的错误提示，可用 errors.Is 判定 ErrEngineNotRegistered。
//
// 开放扩展：应用可经 Register* 系列函数注入自定义引擎（HSM 后端、自定义
// 工作模式等），并用类型转换选中自定义算法，例如
// AsymmetricAlgorithm("ML-KEM")。
//
// # 枚举分工
//
//   - Algorithm（对称，uint8 底层，封闭）：AES128/AES192/AES256/SM4/DES/
//     TripleDES。String() 输出规范名（与 NormalizeAlgorithm 一致），经
//     字符串名桥接 NewCipher/envelope 层；ParseAlgorithm 大小写不敏感、
//     忽略连字符。
//   - Mode（uint8 底层，封闭）：ECB/CBC/CTR/CFB/OFB/GCM。
//   - AsymmetricAlgorithm（string 底层，开放）：预定义常量 RSA/ECDSA/
//     ED25519/SM2/ECDH/X25519 与字符串常量 AlgorithmRSA 等一一对应，
//     自定义算法用类型转换选中。三个入口（NewAsymmetric/NewKeyAgreement/
//     GenerateKeyPair）先查注册表——命中优先于子集判定；未命中才对预定义
//     值做子集校验（如 NewAsymmetric 拒绝 ECDH/X25519）或提示导入引擎包。
//     ParseAsymmetricAlgorithm 对预定义名称归一化（大小写不敏感），非预定义
//     名称原样返回、交由入口查询注册表。
//
// # Encryptor 可复用对象
//
// NewEncryptor 构造一次绑定 算法+模式+密钥+选项，之后可反复调用
// Encrypt/Decrypt（方法级并发安全，无锁）；每次调用内部新建低层模式对象
// 并随即丢弃，对象不持有可变状态。包级 Encrypt/Decrypt 为使用即弃便捷形态
// （内部构造 Encryptor 并立即调用），需要反复加解密同一密钥的调用方请复用
// Encryptor。
//
//	key := []byte("0123456789abcdef")
//	e, err := crypto.NewEncryptor(crypto.AES128, crypto.GCM, crypto.WithKey(key))
//	if err != nil {
//		return err
//	}
//	ct, err := e.Encrypt(plaintext)
//	pt, err := e.Decrypt(ct) // GCM 篡改返回 ErrAuthenticationFailed
//
// 与低层 Cipher/CipherMode 的分层说明：CipherMode（NewGCM/NewCBC 等）在
// 固定 IV/nonce 下仅允许 Encrypt 一次——每次 Encrypt 从相同 IV/nonce 重新
// 初始化，重复 Encrypt 复用完全相同 keystream（C1⊕C2 = P1⊕P2 直接泄露
// 明文）。Encryptor 与协议入口内部使用随机 IV/nonce 变体（每次 Encrypt
// 随机生成并前置），同一对象可安全重复 Encrypt；固定 IV/nonce
// （WithIV/WithNonce）仅为固定格式兼容，禁止在协议中复用同一密钥加密
// 多条消息。
//
// # 模式化加解密 API（Encrypt/Decrypt）
//
// 输出为紧凑格式（不自描述算法与模式，调用方必须持有 algorithm/mode 并在
// Decrypt 时对称传参）：GCM 前置 12B 随机 nonce；CBC/CFB/OFB/CTR 前置
// 块大小随机 IV/计数器；ECB 无前缀。密钥通过四个密钥源选项提供
// （WithKey/WithKeyPassword/WithHexPassword/WithBase64Password）：多个选项
// 按调用顺序后者覆盖前者，缺源返回 ErrKeyRequired；密钥长度按算法严格校验。
//
// # KeyPair 数据契约
//
// KeyPair 在根包定义，含 Reset（敏感内存清零）与 JSON 序列化防护
// （json:"-" + MarshalJSON/UnmarshalJSON 禁止，防止私钥泄露）。编解码、
// 文件读写、格式枚举（PEM/Base64/Hex/Raw）位于 keymgr 子包的函数式 API
// （MarshalPrivateKey/SavePrivateKey/ParsePrivateKeyPair/KeyFormat 等）。
// 注意：gob/yaml 等其他序列化器仍会导出 KeyPair 私钥字段，禁止经其序列化。
//
// # 安全模型
//
// 所有公开 API 均不 panic，错误通过 error 返回。GCM 认证失败统一返回
// ErrAuthenticationFailed；CBC/ECB 填充失败统一 ErrInvalidPadding（错误
// 消息不含细节，防 padding oracle 判据）；密文过短/非对齐返回
// ErrCiphertextTooShort/ErrCiphertextNotAligned。
//
// # 安全策略
//
// 默认拒绝不安全的算法和模式：
//   - DES（已被暴力破解）、TripleDES（安全性下降，块大小仅 8 字节）
//   - ECB（泄露明文模式，相同明文块产生相同密文块）
//
// 对接遗留系统时，传入 WithInsecureAlgorithms() 显式 opt-in：
//
//	ct, err := crypto.Encrypt(crypto.DES, crypto.CBC, pt,
//	    crypto.WithKey(key),
//	    crypto.WithInsecureAlgorithms()) // 显式声明接受风险
//
// # 算法推荐顺序
//
// 推荐使用 SM4 或 AES-GCM：
//   - SM4/AES-GCM：认证加密，安全且高效，首选方案。
//   - CBC：仅用于兼容旧数据格式，新代码不应使用。
//   - CTR：仅用于解密旧格式数据，**禁止用于加密**（nonce 复用会导致明文泄露）。
//   - ECB/DES/3DES：不安全算法，仅兼容遗留数据，新代码**禁用**。
//
// # 已知陷阱
//
//   - bytesconv.BytesResult.String() 返回 Hex 编码字符串，而非原文。
//     如需原文，请使用 []byte 强制转换或 BytesResult.Open() 读取。
//   - DES/3DES 块大小为 8 字节，无法使用 GCM 认证加密。
//   - NormalizeAlgorithm 将泛名 "AES" 归一为 "AES-128"：低层 NewCipher
//     支持 16/24/32 字节密钥（按密钥长度确定实际算法），但泛名传入高层
//     信封 API 时密钥长度必须恰为 16 字节，否则返回密钥长度错误；
//     高层 API 请使用精确算法名（如 "AES-128"/"AES-192"/"AES-256"）。
//   - ECB 模式无随机性，相同明文块产生相同密文块，不推荐使用；
//     NewECB/NewCTR 等入口均已加 Deprecated 警告标注。
//   - CBC/CFB/OFB 使用固定 IV 时，同一 mode 对象仅允许 Encrypt 一次，
//     每条消息应使用新 IV（推荐 WithRandom* 变体或协议入口默认随机路径）。
//
// 高层信封格式（gcx1 自描述信封、fsb1 流式分块 AEAD）位于子包
// github.com/charlienet/go-crypto/crypto/envelope：密文自带算法标识，
// Decrypt 无需算法参数，适合持久化/跨系统使用。桥接示例：
//
//	envelope.Encrypt(crypto.AES128.String(), key, plaintext)
//
// # Examples
//
// ⚠️ 重要提示：使用加密功能前必须导入对应的引擎子包。
// 提供两种模式：
//   - 简单模式：import _ "github.com/charlienet/go-crypto/crypto/engines"（推荐大多数用户）
//   - 精细模式：按需 import _ "github.com/charlienet/go-crypto/crypto/symmetric" 等（需要控制二进制体积）
//
// ## 场景 1：AES-128-GCM 加解密（一次性调用 + 可复用 Encryptor）
//
//	// Example 1: AES-128-GCM encryption and decryption
//	package main
//
//	import (
//		"fmt"
//		"log"
//
//		crypto "github.com/charlienet/go-crypto/crypto"
//		_ "github.com/charlienet/go-crypto/crypto/engines" // Register all official engines
//	)
//
//	func main() {
//		plaintext := []byte("Hello, World!")
//		key := make([]byte, 16) // AES-128 requires 16-byte key
//		// In production, use crypto.GenerateKey("AES-128") or secure random source
//
//		// Method A: One-shot convenience
//		ciphertext, err := crypto.Encrypt(crypto.AES128, crypto.GCM, plaintext, crypto.WithKey(key))
//		if err != nil {
//			log.Fatal(err)
//		}
//
//		decrypted, err := crypto.Decrypt(crypto.AES128, crypto.GCM, ciphertext, crypto.WithKey(key))
//		if err != nil {
//			log.Fatal(err)
//		}
//		fmt.Printf("One-shot: %s\n", decrypted)
//
//		// Method B: Reusable Encryptor (concurrent-safe, better performance)
//		encryptor, err := crypto.NewEncryptor(crypto.AES128, crypto.GCM, crypto.WithKey(key))
//		if err != nil {
//			log.Fatal(err)
//		}
//
//		ct, _ := encryptor.Encrypt(plaintext)
//		pt, _ := encryptor.Decrypt(ct)
//		fmt.Printf("Reusable: %s\n", pt)
//	}
//
// ## 场景 2：SM2 密钥对生成、签名、验签
//
//	// Example 2: SM2 key generation, signing, and verification
//	package main
//
//	import (
//		"fmt"
//		"log"
//
//		crypto "github.com/charlienet/go-crypto/crypto"
//		_ "github.com/charlienet/go-crypto/crypto/engines"
//	)
//
//	func main() {
//		// Generate SM2 key pair
//		keyPair, err := crypto.GenerateKeyPair(crypto.SM2)
//		if err != nil {
//			log.Fatal(err)
//		}
//
//		// Create signer with private key
//		signer, err := crypto.NewAsymmetric(crypto.SM2, crypto.WithPrivateKeyObject(keyPair.PrivateKey))
//		if err != nil {
//			log.Fatal(err)
//		}
//
//		// Sign data
//		message := []byte("Message to sign")
//		signature, err := signer.Sign(message)
//		if err != nil {
//			log.Fatal(err)
//		}
//
//		// Create verifier with public key
//		verifier, err := crypto.NewAsymmetric(crypto.SM2, crypto.WithPublicKeyObject(keyPair.PublicKey))
//		if err != nil {
//			log.Fatal(err)
//		}
//
//		// Verify signature
//		valid := verifier.Verify(message, signature)
//		fmt.Printf("Signature valid: %v\n", valid)
//	}
//
// ## 场景 3：RSA 密钥生成 + PKCS8 导出 + 落盘（PEM + 加密）
//
//	// Example 3: RSA key generation, PKCS8 export, and file storage
//	package main
//
//	import (
//		"fmt"
//		"log"
//		"os"
//
//		crypto "github.com/charlienet/go-crypto/crypto"
//		"github.com/charlienet/go-crypto/crypto/keymgr"
//		_ "github.com/charlienet/go-crypto/crypto/engines"
//	)
//
//	func main() {
//		// Generate RSA-2048 key pair
//		keyPair, err := crypto.GenerateKeyPair(crypto.RSA, crypto.WithKeySize(2048))
//		if err != nil {
//			log.Fatal(err)
//		}
//
//		password := []byte("strong-password")
//
//		// Save private key (PKCS8 + PEM + encrypted)
//		err = keymgr.SavePrivateKey("private.pem", keyPair.PrivateKey, keymgr.KeyFormatPEM,
//			keymgr.WithRSAKeyFormat(keymgr.RSAKeyFormatPKCS8),
//			keymgr.WithEncryptionPassword(password))
//		if err != nil {
//			log.Fatal(err)
//		}
//
//		// Save public key (PEM)
//		err = keymgr.SavePublicKey("public.pem", keyPair.PublicKey, keymgr.KeyFormatPEM)
//		if err != nil {
//			log.Fatal(err)
//		}
//
//		// Load private key
//		loadedKeyPair, err := keymgr.LoadPrivateKeyPair("private.pem", keymgr.KeyFormatPEM,
//			keymgr.WithPassword(password))
//		if err != nil {
//			log.Fatal(err)
//		}
//
//		fmt.Printf("Loaded private key type: %T\n", loadedKeyPair.PrivateKey)
//
//		// Cleanup
//		os.Remove("private.pem")
//		os.Remove("public.pem")
//	}
//
// ## 场景 4：ECDH 密钥协商
//
//	// Example 4: ECDH key agreement
//	package main
//
//	import (
//		"bytes"
//		"fmt"
//		"log"
//
//		crypto "github.com/charlienet/go-crypto/crypto"
//		_ "github.com/charlienet/go-crypto/crypto/engines"
//	)
//
//	func main() {
//		// Alice generates her key pair
//		alice, err := crypto.NewKeyAgreement(crypto.ECDH)
//		if err != nil {
//			log.Fatal(err)
//		}
//		aliceKeyPair, err := alice.GenerateKey()
//		if err != nil {
//			log.Fatal(err)
//		}
//
//		// Bob generates his key pair
//		bob, err := crypto.NewKeyAgreement(crypto.ECDH)
//		if err != nil {
//			log.Fatal(err)
//		}
//		bobKeyPair, err := bob.GenerateKey()
//		if err != nil {
//			log.Fatal(err)
//		}
//
//		// Alice derives shared secret using Bob's public key
//		secretAlice, err := alice.DeriveSharedSecret(bobKeyPair.PublicKey)
//		if err != nil {
//			log.Fatal(err)
//		}
//
//		// Bob derives shared secret using Alice's public key
//		secretBob, err := bob.DeriveSharedSecret(aliceKeyPair.PublicKey)
//		if err != nil {
//			log.Fatal(err)
//		}
//
//		// Both secrets should be identical
//		fmt.Printf("Secrets match: %v\n", bytes.Equal(secretAlice, secretBob))
//	}
//
// ## 场景 5：gcx1 信封加密（含 AAD）
//
//	// Example 5: gcx1 envelope encryption with AAD
//	package main
//
//	import (
//		"fmt"
//		"log"
//
//		"github.com/charlienet/go-crypto/crypto/envelope"
//		_ "github.com/charlienet/go-crypto/crypto/engines"
//	)
//
//	func main() {
//		key := make([]byte, 16) // AES-128 key
//		// In production, use crypto.GenerateKey("AES-128") or secure random source
//
//		plaintext := []byte("Sensitive data")
//		aad := []byte("additional-authenticated-data") // Optional context binding
//
//		// Encrypt with AAD (Authenticated Additional Data)
//		ciphertext, err := envelope.EncryptWithAAD(crypto.AES128, key, plaintext, aad)
//		if err != nil {
//			log.Fatal(err)
//		}
//
//		// Decrypt with AAD (algorithm is self-describing in gcx1 envelope)
//		decrypted, err := envelope.DecryptWithAAD(key, ciphertext, aad)
//		if err != nil {
//			log.Fatal(err)
//		}
//
//		fmt.Printf("Decrypted: %s\n", decrypted)
//
//		// Note: Decrypt without AAD will fail if encrypted with AAD
//		// _, err = envelope.Decrypt(key, ciphertext) // This would fail
//	}
package crypto
