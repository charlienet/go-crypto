// Package envelope 提供高层信封格式实现：gcx1 自描述信封与 fsb1 流式分块 AEAD。
// 底层算法与模式构造位于根包 crypto（NewCipher/NewGCM 等）。
//
// # 安全模型
//
// 高层 API（Encrypt/Decrypt/EncryptWithAAD/DecryptWithAAD）固定使用 GCM
// 认证加密算法，每次加密生成随机 nonce，输出 gcx1 自描述信封格式。
// 所有公开 API 均不 panic，错误通过 error 返回。
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
//   - 高层信封 API（Encrypt/Decrypt/EncryptWithAAD/DecryptWithAAD）的算法名
//     **必须精确指定**（如 "AES-128"/"AES-192"/"AES-256"、"SM4" 等），
//     不可使用泛名。泛名 "AES" 经 crypto.NormalizeAlgorithm 归一为
//     "AES-128"（P3#23 破坏性变更：语义等同 AES-128，密钥长度必须恰为
//     16 字节，否则返回密钥长度错误；需要 AES-192/AES-256 时请改用
//     精确算法名以匹配实际密钥长度）。
//   - DES/3DES 块大小为 8 字节，无法使用 GCM 认证加密，高层 API 返回明确错误。
//
// # gcx1 字节布局（冻结格式）
//
//   - 头部：magic(4B "gcx1") + version(1B) + algID(1B) + nonceLen(1B)，
//     固定 7 字节；随后 nonce(12B) || ciphertext || tag(16B)。
//   - gcx1 v2（version=2）：header 元数据纳入 GCM AAD 认证，篡改 header
//     将导致解密失败；v1 信封（version=1，header 无 AAD 绑定）仍可被兼容
//     读取。新加密输出均为 v2。
//   - fsb1 与 gcx1 格式随 v1.0.0 发布冻结；格式演进通过版本号并存实现，
//     禁止原地修改已冻结格式。
//
// # 冻结格式黄金向量（KAT）
//
// 冻结承诺以**独立锚定的固定字节 KAT** 验证，而非"用当前库现造"的白盒
// 构造（后者与实现同源，格式漂移会同步漂移）：
//
//   - gcx1 v1/v2 KAT（envelope_test.go）：固定 key/明文/布局手工构造的密文
//     hex 字面量，Decrypt 方向断言明文正确，且篡改任一字节必须解密失败。
//   - fsb1 KAT（block_aead_test.go）：固定 key/baseNonce/跨块明文的期望
//     密文流 hex 字面量，Encrypt 方向断言输出一致，且篡改任一字节必须
//     解密失败。
//
// 实现或测试任何一处改动冻结格式（header 布局、版本字节、nonce 派生、
// AAD 语义、块大小、tag 长度），KAT 断言即失败。KAT 常量由当前实现
// 一次性生成后固化为字面量，不依赖运行时生成。
//
// # 信封适配器（EnvelopeCodec）
//
// 本包开放信封适配器注册机制（RegisterEnvelopeCodec），允许应用侧将
// "格式翻译"底层以 codec 形式接入，同时保持高层入口签名不变：
//
//   - 用法：EncryptWith/DecryptWith 按 codec 名分发到对应实现；
//     使用内置保留名 "gcx1" 时，其输出与 Encrypt/Decrypt 完全一致
//     （同一实现，纯转发）。
//   - 选项处理：内置 gcx1 codec 固定使用 GCM 认证加密，**仅 AAD 选项
//     （WithAAD）生效**，其余选项（如 WithPadding 等非 GCM 选项）一律
//     静默忽略，不报错也不影响输出；调用方不应依赖被忽略选项产生效果。
//   - 默认兜底：应用**不注册任何适配器时，默认使用内置 gcx1 实现**，
//     现有 Encrypt/Decrypt 行为不变，无需应用侧任何配置即可用。
//   - 注册时机：建议在 init() 或启动早期一次性注册，先于首次加解密；
//     名称须匹配 ^[a-z][a-z0-9-]{0,63}$，"gcx1" 为库保留名，禁止覆盖。
//
// 适配器实现要求：
//
//   - 无状态、并发安全：同一 codec 实例可被并发调用，内部不得持有可变状态。
//   - 底层必须经 crypto.NewCipher 构造，以继承库内全部输入校验（算法名、
//     密钥长度、nonce/IV 长度、填充校验等）。
//   - 每次调用新建 mode 对象，不得跨调用复用（固定 IV 模式重复 Encrypt
//     会复用 keystream，存在明文泄露风险）。
//   - 返回的错误应包含本格式名前缀（如 "gcx1: ..."），便于定位。
//
// 安全声明：
//
//   - 无认证格式（ECB/CBC/CTR 等）的风险由适配器作者与调用方自行承担，
//     本包不内置任何无认证 codec。
//   - 适配器交付须附跨实现互操作向量测试（固定密钥/明文/随机数下的
//     期望密文断言），防止格式漂移。
//
// # fsb2 自描述文件容器（推荐，v1.0.0 起）
//
// fsb2 是 fsb1 的演进格式：固定 28 字节文件头内嵌全部带外元数据，
// 加密/解密两端不再需要外部传递 baseNonce/明文总长/算法标识，
// 解密侧构造器只收密钥（totalSize/baseNonce 从密文流自读）。
//
// # fsb2 头部字节布局（冻结格式）
//
//	offset  size  field
//	0       6     magic "GOFSB2"
//	6       1     version（0x00，首版冻结）
//	7       1     algID（查表映射 symmetric 注册键）
//	8       12    baseNonce（随机 12 字节）
//	20      8     明文总长（uint64 小端）
//
// 头部共 28 字节；分块大小固定 ChunkSize(4096)（与 fsb1 一致，常量不可
// 配置），不入头部。头部整体（28 字节）作为每块 GCM AAD 前缀绑定
// （参照 gcx1 v2 的 header 入 AAD 防篡改做法），块号以 BE64 追加在尾——
// 篡改头部任一字节（含算法混淆、长度回滚）都会被对应块的 GCM 认证拒绝。
//
// baseNonce 由 NewFileEncrypter 内部经 crypto/rand 生成并写入头部，
// 每次加密独立随机，调用方无需（也不应）自行提供，消除 fsb1 的 nonce
// 复用责任。算法 ID 与密钥长度在两侧入口严格校验（对齐 Lane A 的
// Insecure 元数据闸门），DES/3DES 等不安全算法在头部校验处被拒绝。
//
// # 用法示例（大文件加密）
//
//	package main
//
//	import (
//		"fmt"
//		"io"
//		"log"
//		"os"
//
//		"github.com/charlienet/go-crypto/envelope"
//	)
//
//	func main() {
//		key := make([]byte, 16) // AES-128
//		src, _ := os.Open("plaintext.bin")
//		defer src.Close()
//		stat, _ := src.Stat()
//
//		// 加密：构造器自管 nonce/算法；仅需声明明文总长（写入头部）
//		enc, err := envelope.NewFileEncrypter(key, "AES-128")
//		if err != nil {
//			log.Fatal(err)
//		}
//		encReader, err := enc.Encrypt(src, stat.Size())
//		if err != nil {
//			log.Fatal(err)
//		}
//		dst, _ := os.Create("encrypted.bin")
//		defer dst.Close()
//		// 密文长度可预知（含 28 字节头部），可作 S3 PutObject ContentLength
//		fmt.Printf("Encrypted size: %d bytes\n", encReader.Length())
//		io.Copy(dst, encReader)
//
//		// 解密：只收密钥，头部（magic/version/algID/baseNonce/totalSize）
//		// 从密文流自读并校验，构造时无需任何带外参数
//		encFile, _ := os.Open("encrypted.bin")
//		defer encFile.Close()
//		decReader, err := envelope.NewFileDecryptingReader(encFile, key)
//		if err != nil {
//			log.Fatal(err)
//		}
//		out, _ := os.Create("decrypted.bin")
//		defer out.Close()
//		io.Copy(out, decReader)
//
//		os.Remove("encrypted.bin")
//		os.Remove("decrypted.bin")
//	}
//
// # fsb1 流式分块 AEAD（遗留，已冻结）
//
// ⚠️ 遗留格式：密文流无容器头部，baseNonce/明文总长/算法标识全部带外
// 管理，解密构造必须外部传入 totalSize——评审 #2 指出的误用根因。
// **新集成请使用上方 fsb2 自描述容器**；fsb1 仅保留存量数据兼容，
// 格式冻结只读，禁止改动。
//
// 明文按 ChunkSize(4096) 分块，每块使用 AES/SM4-GCM 独立加密，输出连续的
// "密文块 || 16 字节认证标签"流。块 nonce 由 baseNonce（12 字节）视为
// 大端 96 位整数按块号递增派生，AAD 绑定格式魔数、明文总长与块号，
// 用于防重排、截断与拼接。
//
// # fsb1 baseNonce 唯一性职责
//
// 使用 fsb1 流式加密时，调用方**必须**保证 baseNonce 在密钥生命周期内唯一。
// nonce 复用将导致 GCM 认证失效，可能泄露明文。
//
// # 场景 6：fsb1 流式分块 AEAD（遗留示例，新集成改用 fsb2）
//
//	package main
//
//	import (
//		"bytes"
//		"crypto/rand"
//		"fmt"
//		"io"
//		"log"
//		"os"
//
//		crypto "github.com/charlienet/go-crypto"
//		"github.com/charlienet/go-crypto/envelope"
//		_ "github.com/charlienet/go-crypto/engines"
//	)
//
//	func main() {
//		// 准备密钥和 nonce
//		key := make([]byte, 16) // AES-128
//		baseNonce := make([]byte, 12)
//		if _, err := rand.Read(baseNonce); err != nil {
//			log.Fatal(err)
//		}
//		// ⚠️ 同一密钥下 baseNonce 绝对不可复用：fsb1 的块 nonce 由
//		// baseNonce 按块号递增派生，baseNonce 复用等价于 GCM nonce 复用，
//		// 将导致认证失效甚至明文泄露。建议每次加密生成随机 baseNonce，
//		// 并随密文带外持久化，解密时再传入。
//		// ⚠️ 迁移提示：fsb1 为遗留格式（nonce/长度/算法全部带外管理），
//		// 新集成请改用 fsb2（NewFileEncrypter/NewFileDecryptingReader）：
//		// baseNonce 由库内随机生成并写入容器头部，无需（也不应）自行提供。
//		// 在真实场景中，使用 crypto.GenerateKey("AES-128") 生成密钥。
//
//		// 创建 Cipher 对象
//		cipher, err := crypto.NewCipher("AES-128", key)
//		if err != nil {
//			log.Fatal(err)
//		}
//
//		// 加密：从文件读取，写入加密文件
//		src, _ := os.Open("plaintext.bin")
//		defer src.Close()
//
//		stat, _ := src.Stat()
//		totalSize := stat.Size()
//
//		encReader, err := envelope.NewEncryptingReader(src, cipher, baseNonce, totalSize)
//		if err != nil {
//			log.Fatal(err)
//		}
//
//		dst, _ := os.Create("encrypted.bin")
//		defer dst.Close()
//
//		// 可预知密文长度
//		cipherLen := encReader.Length()
//		fmt.Printf("Encrypted size: %d bytes\n", cipherLen)
//
//		io.Copy(dst, encReader)
//
//		// 解密：从加密文件读取，写入解密文件
//		encFile, _ := os.Open("encrypted.bin")
//		defer encFile.Close()
//
//		decReader, err := envelope.NewDecryptingReader(encFile, cipher, baseNonce, totalSize)
//		if err != nil {
//			log.Fatal(err)
//		}
//
//		out, _ := os.Create("decrypted.bin")
//		defer out.Close()
//
//		io.Copy(out, decReader)
//
//		// 清理
//		os.Remove("encrypted.bin")
//		os.Remove("decrypted.bin")
//	}
//
// # hyb1 数字信封（公钥信封，v1.0.0 起）
//
// hyb1 是混合加密（KEM + AEAD）信封：给"公钥持有者"加密（大）数据的
// 一站式 API。Seal 内部自动完成密钥封装（RSA-OAEP 或 X25519 临时-静态
// ECDH）与随机 DEK 的对称 GCM 载荷加密，输出自描述单条 []byte，杜绝
// 调用方手拼 RSA-OAEP + AES。
//
// # 三种信封格式的关系
//
//   - gcx1：共享密钥小报文（对称密钥、直接 GCM、35 字节开销）。
//   - fsb2：文件流（对称密钥、分块 GCM、流式大文件、头部自描述）。
//   - hyb1：公钥信封（公钥 → 随机 DEK → 对称 GCM 载荷，单条密封结果）。
//
// hyb1 与 fsb1/fsb2 互补不冲突：hyb1 解决"公钥分发数据密钥"，fsb2 解决
// "大文件流式加密"；两者组合见下文"公钥 + 大文件"。
//
// # hyb1 字节布局（冻结格式，多字节字段均为大端序）
//
//	offset  size  field
//	0       4     magic "GCHY"
//	4       1     version（0x00，首版冻结）
//	5       1     kemID（0x01=RSA-OAEP(SHA-256)；0x02=X25519 临时-静态 ECDH）
//	6       1     payloadAlgID（0x01=SM4-GCM(DEK 16B)；0x02=AES-256-GCM(DEK 32B)）
//	7       2     ephPub 长度（BE16）
//	9       n     ephPub（X25519=32B；RSA 路径 n=0）
//	9+n     2     nonce 长度（BE16）
//	11+n    m     nonce（X25519=12B wrap GCM nonce；RSA 路径 m=0）
//	11+n+m  2     encDEK 长度（BE16）
//	13+n+m  k     encDEK（X25519 = ct‖tag；RSA = OAEP 密文）
//	13+n+m+k  L   payload：nonce(12B) ‖ GCM 密文 ‖ tag(16B)
//
// payload GCM 的 AAD = 完整头部（7B）‖ 用户 AAD（头部整体入 AAD，
// 参照 gcx1 v2 / fsb2 的 header 入 AAD 防篡改做法）。X25519 路径的
// wrap key = HKDF-SHA256(shared, salt=头部 7B, info="GCHY-hyb1-dek")
// （32B），以 AES-256-GCM(wrap key, 12B 随机 nonce) 加密 DEK。
//
// # 用法示例（公钥加密报文）
//
//	package main
//
//	import (
//		"crypto/ecdh"
//		"crypto/rand"
//		"fmt"
//		"log"
//
//		"github.com/charlienet/go-crypto/envelope"
//	)
//
//	func main() {
//		// 收件人公钥（X25519；传 *rsa.PublicKey 亦可走 RSA-OAEP 路径）。
//		// 演示用临时密钥；生产环境公钥应来自受信通道（证书/密钥服务器）。
//		priv, err := ecdh.X25519().GenerateKey(rand.Reader)
//		if err != nil {
//			log.Fatal(err)
//		}
//		pub := priv.PublicKey()
//
//		sealed, err := envelope.Seal(pub, []byte("机密数据"), []byte("上下文AAD"))
//		if err != nil {
//			log.Fatal(err)
//		}
//		fmt.Printf("信封: %x\n", sealed)
//
//		plain, err := envelope.Open(priv, sealed, []byte("上下文AAD"))
//		if err != nil {
//			log.Fatal(err)
//		}
//		fmt.Printf("明文: %s\n", plain)
//	}
//
// # "公钥 + 大文件"组合建议
//
// hyb1 密封结果为单条内存块，适合中小报文；大文件推荐组合方案：
//
//  1. hyb1.Seal 密封随机 DEK（小开销，约数百字节）；
//  2. 以该 DEK 走 fsb2（NewFileEncrypter / NewFileDecryptingReader）
//     流式加密文件；
//  3. 持久化 hyb1 信封 + fsb2 密文文件，解密时 Open 得 DEK 再解 fsb2。
//
// 注意：当前版本收件人侧无法直接从 hyb1 信封取出 DEK（Open 只返回明文、
// 不暴露 DEK），故上述组合要求发送方取得 DEK 后再加密大文件。DEK 外提
// 接口（如 SealDEK/OpenDEK 拆分：仅封装 DEK 的信封 + 单独载荷解密入口，
// 使"发送方仅加密小信封、收件人解密大文件"成为可能）预留为未来扩展，
// 不在此版本实现——届时可演进为"hyb1 仅封 DEK，载荷段交由 fsb2 消费"。
//
// # HPKE 公钥信封（RFC 9180 Base 模式，v0.3.0 起）
//
// HPKE（Hybrid Public Key Encryption）是 IETF RFC 9180 标准协议，提供
// "给公钥持有者加密"的一站式 API。本实现基于 Cloudflare CIRCL 库，
// 支持 DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-256-GCM 组合。
//
// HPKE 与 hyb1 的区别：
//   - hyb1：go-crypto 自定义格式，支持 RSA-OAEP 和 X25519 两种 KEM，
//     输出自描述信封（含 magic/version/算法标识）。
//   - HPKE：RFC 9180 标准格式，仅 X25519 KEM，输出 enc(32B) ‖ ciphertext，
//     适合跨库互操作（与其他 RFC 9180 实现兼容）。
//
// # HPKE 输出格式
//
// HPKESeal 返回两个独立切片：enc（32B 临时公钥）和 ciphertext（密文）。
// 调用方需自行持久化 enc 以便接收方解密。若需自描述单条格式，请使用 hyb1。
//
// # 用法示例（HPKE）
//
//	package main
//
//	import (
//		"crypto/ecdh"
//		"crypto/rand"
//		"fmt"
//		"log"
//
//		"github.com/charlienet/go-crypto/envelope"
//	)
//
//	func main() {
//		// 收件人 X25519 密钥对
//		priv, err := ecdh.X25519().GenerateKey(rand.Reader)
//		if err != nil {
//			log.Fatal(err)
//		}
//		pub := priv.PublicKey()
//
//		// 加密
//		suite := envelope.HPKE_X25519_HKDF_SHA256_AES_256_GCM
//		enc, ciphertext, err := envelope.HPKESeal(suite, pub, []byte("机密数据"), []byte("上下文info"))
//		if err != nil {
//			log.Fatal(err)
//		}
//		fmt.Printf("enc: %x, ciphertext: %x\n", enc, ciphertext)
//
//		// 解密
//		plain, err := envelope.HPKEOpen(suite, priv, enc, ciphertext, []byte("上下文info"))
//		if err != nil {
//			log.Fatal(err)
//		}
//		fmt.Printf("明文: %s\n", plain)
//	}
//
// # ECIES 公钥信封（P-256，v0.3.0 起）
//
// ECIES（Elliptic Curve Integrated Encryption Scheme）基于 P-256 临时-静态
// ECDH，适合需要 NIST 曲线兼容的场景。算法组合：
//
//	ephemeral ECDH P-256 → HKDF-SHA256(16B) → AES-128-GCM
//
// ECIES 与 hyb1/HKPE 的区别：
//   - hyb1：go-crypto 自定义格式，支持 RSA/X25519，输出自描述信封。
//   - HPKE：RFC 9180 标准，仅 X25519，适合跨库互操作。
//   - ECIES：P-256 曲线，适合 NIST 合规场景（如 FIPS 140-2）。
//
// # ECIES 输出格式（冻结格式）
//
//	offset  size  field
//	0       1     ephPubLen = 0x41 (65)
//	1       65    ephPub（P-256 未压缩点：0x04 ‖ X(32B) ‖ Y(32B)）
//	66      12    nonce（AES-GCM 随机 nonce）
//	78      L     ciphertext（GCM 密文）
//	78+L    16    tag（GCM 认证标签）
//
// 总长度：94 + len(plaintext) 字节。
//
// # 用法示例（ECIES）
//
//	package main
//
//	import (
//		"crypto/ecdsa"
//		"crypto/elliptic"
//		"crypto/rand"
//		"fmt"
//		"log"
//
//		"github.com/charlienet/go-crypto/envelope"
//	)
//
//	func main() {
//		// 收件人 P-256 密钥对
//		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
//		if err != nil {
//			log.Fatal(err)
//		}
//
//		// 加密（可选 AAD 绑定上下文）
//		sealed, err := envelope.ECIESSeal(&priv.PublicKey, []byte("机密数据"), []byte("上下文AAD"))
//		if err != nil {
//			log.Fatal(err)
//		}
//		fmt.Printf("信封: %x\n", sealed)
//
//		// 解密（须传相同 AAD）
//		plain, err := envelope.ECIESOpen(priv, sealed, []byte("上下文AAD"))
//		if err != nil {
//			log.Fatal(err)
//		}
//		fmt.Printf("明文: %s\n", plain)
//	}
//
// # 四种信封格式选型指南
//
//   - gcx1：共享密钥小报文（对称密钥、直接 GCM、35 字节开销）。
//   - fsb2：大文件流式加密（对称密钥、分块 GCM、流式、头部自描述）。
//   - hyb1：公钥信封（RSA/X25519 KEM + AES-GCM 载荷，go-crypto 自定义格式）。
//   - HPKE：公钥信封（X25519 KEM，RFC 9180 标准，跨库互操作）。
//   - ECIES：公钥信封（P-256 KEM，NIST 合规场景）。
package envelope
