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
//     不可使用泛名。泛名 "AES" 仅低层 crypto.NewCipher 支持（允许 16/24/32
//     字节密钥，按密钥长度确定实际算法）。高层 API 传入泛名 "AES" 时，
//     crypto.NormalizeAlgorithm 会将其归一化为 "AES-128"：若密钥长度恰为
//     16 字节则正常加密，否则返回密钥长度错误
//     （如 "invalid key length 24 for AES-128, want 16"），
//     此时应改用精确算法名（如 AES-192/AES-256）以匹配实际密钥长度。
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
// # fsb1 流式分块 AEAD
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
// # 场景 6：fsb1 流式分块 AEAD（大文件加密）
//
//	package main
//
//	import (
//		"bytes"
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
//		// 在真实场景中，使用 crypto.GenerateKey("AES-128") 和随机 nonce
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
package envelope
