# go-crypto

Go 密码学库，提供对称/非对称加密、密钥协商、密钥派生、信封加密与国密算法（SM2/SM3/SM4）。所有算法实现位于子包，经根包注册表统一分发（database/sql driver 模式）。

## 安装

要求 Go 1.25+（见 go.mod）。

```bash
go get github.com/charlienet/go-crypto
```

## 包列表

| 包 | 说明 |
|---|------|
| [crypto](./)（模块根） | 契约层：接口、枚举、选项、错误哨兵、引擎注册表与协议入口（Encrypt/NewEncryptor/NewAsymmetric/NewKeyAgreement/GenerateKeyPair/KeySize）、KeyPair.AsSigner 标准库 crypto.Signer 视图 |
| [symmetric](./symmetric) | 对称算法引擎（AES-128/192/256、SM4、DES/3DES）与工作模式（GCM/CBC/CTR/CFB/OFB/ECB） |
| [asym](./asym) | 非对称算法引擎（RSA、ECDSA、Ed25519、SM2） |
| [agreement](./agreement) | 密钥协商引擎（ECDH、X25519、SM2） |
| [keymgr](./keymgr) | 密钥对生成、编解码、落盘（PEM/Base64/Hex/Raw）、PBES2 私钥加密 |
| [envelope](./envelope) | 高层信封格式：gcx1 自描述信封、fsb2 自描述文件容器（流式分块 AEAD）、hyb1 公钥混合加密信封（KEM+AEAD） |
| [hash](./hash) | 哈希函数（MD5/SHA 系/SM3/Murmur3/XXHash/FNV） |
| [hmac](./hmac) | HMAC 消息认证码（支持 SM3 等） |
| [kdf](./kdf) | 密钥派生（HKDF、PBKDF2、Argon2id）、高层 DeriveKey 与 PHC 标准格式口令哈希（PasswordHash/PasswordVerify） |
| [engines](./engines) | 一键 blank import 注册全部官方引擎 |
| [common](./common) | 内部共享工具（随机数、内存清零） |

## 特性

- **对称加密**：AES-128/192/256、SM4，GCM/CBC 等模式；DES/3DES、ECB 默认拒绝，需显式 opt-in；`KeySize(algorithm)` 经注册表查询算法严格密钥长度（另有 `Algorithm.KeySize()` 方法与 `WithKeySize(bits)` 密钥生成选项）
- **非对称加密/签名**：RSA（OAEP/PSS）、ECDSA、Ed25519、SM2；`KeyPair.AsSigner()` 返回标准库 crypto.Signer 视图，可直接接入 TLS/JWT 等标准生态
- **密钥协商**：ECDH、X25519、SM2
- **密钥派生**：HKDF、PBKDF2、Argon2id
- **口令哈希（PHC）**：`kdf.PasswordHash` 输出 PHC 标准格式（`$argon2id$v=19$m=...`），salt/参数/派生结果自包含存储；默认参数基线对齐 OWASP 2024（argon2id m=64MiB、t=3、p=4）
- **密钥管理**：PKCS#8/PKCS#1、PEM 加密（PBES2）
- **信封加密**：gcx1 自描述格式（密文自带算法标识）、fsb2 自描述文件容器（fsb1 演进格式，28 字节头部内嵌算法/baseNonce/明文总长，解密侧只收密钥）、hyb1 公钥混合加密信封（RSA-OAEP 或 X25519 临时-静态 ECDH 密钥封装 + AES-256-GCM/SM4-GCM 载荷）
- **哈希/HMAC**：MD5、SHA-1/224/256/384/512、SM3、Murmur3、XXHash、FNV
- **安全默认**：所有公开 API 不 panic；GCM 认证失败统一哨兵；密钥内存清零

## 使用示例

> **重要**：通过根包协议入口使用前，须先导入引擎子包。最简单方式是一键导入
> `_ "github.com/charlienet/go-crypto/engines"`（注册全部官方引擎）；需要控制
> 二进制体积时可按需逐个 blank import（symmetric/asym/agreement/keymgr）。

### 对称加密（AES-128-GCM）

```go
import (
	crypto "github.com/charlienet/go-crypto"
	_ "github.com/charlienet/go-crypto/engines" // 注册全部官方引擎
)

key := []byte("0123456789abcdef") // AES-128 需要 16 字节密钥

// 一次性加解密
ciphertext, err := crypto.Encrypt(crypto.AES128, crypto.GCM, plaintext, crypto.WithKey(key))
plaintext, err = crypto.Decrypt(crypto.AES128, crypto.GCM, ciphertext, crypto.WithKey(key))

// 可复用 Encryptor（构造一次，反复调用，方法级并发安全）
e, err := crypto.NewEncryptor(crypto.AES128, crypto.GCM, crypto.WithKey(key))
ct, _ := e.Encrypt(plaintext)
pt, _ := e.Decrypt(ct)
```

### 非对称加密（SM2 签名/验签）

```go
import (
	crypto "github.com/charlienet/go-crypto"
	_ "github.com/charlienet/go-crypto/engines"
)

// 生成密钥对（返回 (*KeyPair, error)，私钥对象在 KeyPair.PrivateKey）
keyPair, err := crypto.GenerateKeyPair(crypto.SM2)

// 签名
signer, err := crypto.NewAsymmetric(crypto.SM2, crypto.WithPrivateKeyObject(keyPair.PrivateKey))
signature, err := signer.Sign(message)

// 验签
verifier, err := crypto.NewAsymmetric(crypto.SM2, crypto.WithPublicKeyObject(keyPair.PublicKey))
valid := verifier.Verify(message, signature)

// 标准库互通：获取 crypto.Signer 视图（支持 RSA/ECDSA/Ed25519/SM2），
// 可直接传入 tls.Certificate / JWT 等；X25519/ECDH 密钥返回 ErrKeyPairNotSigner
// 注意：crypto.Signer 的 Sign 接收已哈希摘要，与上方 Asymmetric.Sign(msg) 语义不同
stdSigner, err := keyPair.AsSigner()
```

### 哈希函数

```go
import "github.com/charlienet/go-crypto/hash"

d1 := hash.Sha256([]byte("hello")) // 摘要展示/存储请用 .Hex()，String() 是带转义的引号形式
d2 := hash.Sm3([]byte("hello"))
```

### HMAC

```go
import "github.com/charlienet/go-crypto/hmac"

c, err := hmac.New("HMACSHA256", key) // 算法名大小写不敏感，支持 SM3（HMACSM3）
sign, err := c.Sign([]byte("message"))
ok := c.Verify([]byte("message"), sign)
```

### 密钥派生

```go
import "github.com/charlienet/go-crypto/kdf"

// Argon2id（推荐用于密码）
key, err := kdf.Argon2id([]byte("password"), salt, 3, 64*1024, 4, 32)

// HKDF（用于密钥扩展；首参为哈希算法名字符串）
encKey, err := kdf.HKDF("SHA-256", sharedSecret, nil, []byte("encryption"), 16)

// PBKDF2（迭代次数建议 ≥ 600000，OWASP 2024 建议）
key, err := kdf.PBKDF2([]byte("password"), salt, 600000, 16)
```

### 信封加密（gcx1）

```go
import (
	crypto "github.com/charlienet/go-crypto"
	"github.com/charlienet/go-crypto/envelope"
	_ "github.com/charlienet/go-crypto/engines"
)

// 密文自带算法标识，解密无需算法参数，适合持久化/跨系统
ciphertext, err := envelope.Encrypt(crypto.AES128, key, plaintext)
plaintext, err := envelope.Decrypt(key, ciphertext)
```

### 文件加密（fsb2）

```go
import (
	"fmt"
	"io"
	"os"

	"github.com/charlienet/go-crypto/envelope"
)

key := make([]byte, 16) // AES-128（真实场景用 crypto.GenerateKey 生成）

// 加密：28 字节头部自嵌算法/baseNonce/明文总长，baseNonce 由库内随机生成
src, _ := os.Open("plaintext.bin")
defer src.Close()
stat, _ := src.Stat()

enc, err := envelope.NewFileEncrypter(key, "AES-128")
encReader, err := enc.Encrypt(src, stat.Size())
fmt.Printf("Encrypted size: %d bytes\n", encReader.Length()) // 密文长度可预知
dst, _ := os.Create("encrypted.bin")
defer dst.Close()
io.Copy(dst, encReader)

// 解密：只收密钥，头部元数据从密文流自读并校验（fsb1 需带外传 baseNonce/totalSize）
encFile, _ := os.Open("encrypted.bin")
defer encFile.Close()
decReader, err := envelope.NewFileDecryptingReader(encFile, key)
out, _ := os.Create("decrypted.bin")
defer out.Close()
io.Copy(out, decReader)
```

### 混合加密信封（hyb1）

```go
import (
	"crypto/ecdh"
	"crypto/rand"

	"github.com/charlienet/go-crypto/envelope"
)

// 收件人公钥（传 *rsa.PublicKey 走 RSA-OAEP 路径；X25519 走临时-静态 ECDH）
priv, err := ecdh.X25519().GenerateKey(rand.Reader)
pub := priv.PublicKey()

// 封装 + 载荷 GCM 加密一步完成，输出自描述单条密文
sealed, err := envelope.Seal(pub, []byte("机密数据"), []byte("上下文AAD"))

// 收件人解封（aad 须与封装时一致）
plain, err := envelope.Open(priv, sealed, []byte("上下文AAD"))
```

### 口令哈希（PHC）

```go
import "github.com/charlienet/go-crypto/kdf"

// 输出 PHC 标准格式字符串（salt/参数/哈希自包含），默认参数对齐 OWASP 2024
ph, err := kdf.PasswordHash([]byte("user-password"), nil)
// 形如 $argon2id$v=19$m=65536,t=3,p=4$<b64(salt)>$<b64(hash)>，直接入库存储

ok, err := kdf.PasswordVerify(ph, []byte("user-password")) // 无状态验证，常量时间比对

// 登录成功后检查参数是否落后于当前基线，true 则重哈希更新存储
need, err := kdf.PasswordNeedsRehash(ph, nil)
```

## 依赖

- Go 1.25+
- github.com/charlienet/go-utils（bytex 字节工具）
- github.com/emmansun/gmsm（国密算法 SM2/SM3/SM4）
- golang.org/x/crypto（HKDF、PBKDF2、Argon2）

## 安全说明

- 默认拒绝不安全算法/模式（DES、3DES、ECB），需显式 `WithInsecureAlgorithms()` 才可启用
- GCM 认证失败统一返回 `ErrAuthenticationFailed`；CBC/ECB 填充失败统一 `ErrInvalidPadding`（错误消息不含细节，防 padding oracle 判据）
- 固定 IV/nonce 下同一密钥禁止加密多条消息（keystream 复用直接泄露明文）
- 私钥内存清零；KeyPair 禁止经 gob/yaml 等序列化
- 使用 `crypto/engines` 一键注册全部引擎
- 常量时间 PKCS7 校验（防 padding oracle 攻击）
- 口令哈希验证（`kdf.PasswordVerify`）先校验参数上限拒绝恶意存储串（防解析 DoS），再以常量时间比对；默认参数基线为 OWASP 2024（argon2id m=64MiB、t=3、p=4）

## License

MIT License