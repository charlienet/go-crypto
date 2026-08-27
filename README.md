# go-crypto

Go 密码学库，提供完整的加密算法实现，支持国密算法。

## 安装

```bash
go get github.com/charlienet/go-crypto
```

## 包列表

| 包 | 说明 |
|---|------|
| [crypto](./crypto) | 完整密码学框架 |
| [hash](./hash) | 哈希函数（MD5/SHA/SM3/Murmur3/XXHash） |
| [hmac](./hmac) | HMAC 消息认证码 |

## 特性

- **对称加密**：AES-128/192/256、SM4、DES/3DES
- **非对称加密**：RSA、ECDSA、Ed25519、SM2
- **密钥协商**：ECDH、X25519、SM2
- **密钥派生**：HKDF、PBKDF2、Argon2id
- **信封加密**：gcx1 自描述格式、fsb1 流式分块 AEAD
- **哈希函数**：MD5、SHA-1/256/384/512、SM3、Murmur3、XXHash
- **HMAC**：支持多种哈希算法

## 使用示例

### 对称加密（AES-128-GCM）

```go
import (
    "github.com/charlienet/go-crypto/crypto"
    _ "github.com/charlienet/go-crypto/crypto/engines"
)

// 创建加密器
encryptor, err := crypto.NewEncryptor(crypto.AES128, crypto.GCM, crypto.WithKey(key))

// 加密
ciphertext, err := encryptor.Encrypt(plaintext)

// 解密
plaintext, err := encryptor.Decrypt(ciphertext)
```

### 非对称加密（SM2）

```go
import "github.com/charlienet/go-crypto/crypto"

// 生成密钥对
privateKey, publicKey, err := crypto.GenerateKeyPair(crypto.SM2)

// 创建签名器
signer, err := crypto.NewAsymmetric(crypto.SM2, crypto.WithPrivateKey(privateKey))

// 签名
signature, err := signer.Sign(message)

// 验签
verifier, err := crypto.NewAsymmetric(crypto.SM2, crypto.WithPublicKey(publicKey))
valid := verifier.Verify(message, signature)
```

### 哈希函数

```go
import "github.com/charlienet/go-crypto/hash"

// SHA-256
result := hash.Sha256([]byte("hello"))

// SM3（国密）
result := hash.Sm3([]byte("hello"))
```

### HMAC

```go
import "github.com/charlienet/go-crypto/hmac"

// HMAC-SHA256
result := hmac.Sha256(key, []byte("message"))
```

### 密钥派生

```go
import "github.com/charlienet/go-crypto/crypto/kdf"

// Argon2id（推荐用于密码）
key, err := kdf.Argon2id([]byte("password"), salt, 3, 64*1024, 4, 32)

// HKDF（用于密钥扩展）
key, err := kdf.HKDF(sha256.New, ikm, salt, info, 32)
```

## 依赖

- Go 1.21+
- github.com/charlienet/go-utils
- github.com/emmansun/gmsm（国密算法）
- golang.org/x/crypto（HKDF、PBKDF2、Argon2）

## 安全说明

- 默认拒绝不安全算法（DES、3DES、ECB），需要显式启用
- 使用 `crypto/engines` 包自动注册所有引擎
- 支持密钥内存清零
- 常量时间 PKCS7 校验（防 padding oracle 攻击）

## License

MIT License
