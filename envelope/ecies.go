package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"github.com/charlienet/go-crypto/common"
)

// ECIES（Elliptic Curve Integrated Encryption Scheme）基于 P-256 临时-静态 ECDH。
//
// 定位：给 P-256 公钥持有者加密数据的轻量 API。内部自动完成 ECDH 密钥协商
// 与 AES-128-GCM 认证加密，输出自描述单条 []byte，无需调用方手拼协议。
//
// 安全模型：
//   - 前向保密：每封信封生成全新临时密钥对，单次私钥泄露不影响历史信封
//   - IND-CCA2：AES-GCM 认证加密防篡改，AAD 可选绑定外部上下文
//   - 密钥派生：HKDF-SHA256 域名分离（info="go-crypto-ecies"）
//
// 字节布局（冻结格式，无版本号——算法绑定曲线）：
//
//	offset  size  field
//	0       1     ephPubLen = 0x41 (65)
//	1       65    ephPub（P-256 未压缩点：0x04 ‖ X(32B) ‖ Y(32B)）
//	66      12    nonce（AES-GCM 随机 nonce）
//	78      L     ciphertext（GCM 密文）
//	78+L    16    tag（GCM 认证标签）
//
// 总长度：1 + 65 + 12 + len(plaintext) + 16 = 94 + len(plaintext)
//
// AAD 绑定：用户 AAD 参与 GCM 认证但不入信封，Open 时须传相同值。
// nil AAD 与空 AAD 等价（底层 GCM 实现区分，但本 API 视为等价）。
//
// 曲线限制：仅接受 P-256（secp256r1），拒绝其他曲线（P-384、P-521、X25519 等）。

const (
	eciesEphPubLen    = 65  // P-256 未压缩点长度（0x04 ‖ X ‖ Y）
	eciesNonceLen     = 12  // AES-GCM nonce 长度
	eciesTagLen       = 16  // AES-GCM 认证标签长度
	eciesDEKLen       = 16  // AES-128 密钥长度
	eciesMinSealedLen = 1 + eciesEphPubLen + eciesNonceLen + eciesTagLen // 94
)

// eciesHKDFInfo HKDF info 参数，域名分离防与库内其他 HKDF 用途串义。
const eciesHKDFInfo = "go-crypto-ecies"

var (
	// ErrECIESTooShort 信封数据过短（< 94 字节）或 ephPubLen 字段不匹配。
	ErrECIESTooShort = errors.New("ecies: sealed data too short")
	// ErrECIESInvalidCurve 仅支持 P-256 曲线，其他曲线密钥被拒绝。
	ErrECIESInvalidCurve = errors.New("ecies: only P-256 curve supported")
	// ErrECIESInvalidEphPub 临时公钥非法（非有效 P-256 点）。
	ErrECIESInvalidEphPub = errors.New("ecies: invalid ephemeral public key")
	// ErrECIESAuthFailed 认证失败（GCM tag 校验失败或密钥不匹配）。
	ErrECIESAuthFailed = errors.New("ecies: authentication failed")
)

// ECIESSeal 使用收件人 P-256 公钥加密明文，输出 ECIES 信封（[]byte）。
//
// recipientPub 必须为 P-256 曲线的 *ecdsa.PublicKey，其他曲线返回 ErrECIESInvalidCurve。
// aad 参与 GCM 认证但不入信封，Open 时须传相同值（nil 与空等价）。
//
// 安全保证：
//   - 前向保密：每封信封生成全新临时密钥对
//   - 密钥派生：HKDF-SHA256(shared, nil, "go-crypto-ecies") → 16B DEK
//   - 认证加密：AES-128-GCM，nonce 随机生成（12B）
//   - 敏感内存清零：临时私钥、共享密钥、DEK 用后擦除
//
// 输出格式：ephPubLen(1B) ‖ ephPub(65B) ‖ nonce(12B) ‖ ciphertext ‖ tag(16B)
func ECIESSeal(recipientPub *ecdsa.PublicKey, plaintext, aad []byte) ([]byte, error) {
	// 校验曲线必须为 P-256
	if recipientPub == nil || recipientPub.Curve == nil {
		return nil, ErrECIESInvalidCurve
	}
	if recipientPub.Curve != elliptic.P256() {
		return nil, ErrECIESInvalidCurve
	}

	// 转换 ecdsa 公钥为 ecdh 公钥
	ecdhPub, err := recipientPub.ECDH()
	if err != nil {
		return nil, ErrECIESInvalidCurve
	}

	// 1. 生成临时 P-256 密钥对
	ephPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	ephPubBytes := ephPriv.PublicKey().Bytes()

	// 确保临时私钥用后清零（defer 安排在错误路径之前）
	defer func() {
		common.ZeroBytes(ephPriv.Bytes())
	}()

	// 2. ECDH 密钥协商
	shared, err := ephPriv.ECDH(ecdhPub)
	if err != nil {
		return nil, err
	}
	defer func() {
		common.ZeroBytes(shared)
	}()

	// 3. HKDF-SHA256 派生 DEK（16B）
	dek, err := eciesDeriveKey(shared)
	if err != nil {
		return nil, err
	}
	defer func() {
		common.ZeroBytes(dek)
	}()

	// 4. AES-128-GCM 加密
	ciphertext, nonce, err := eciesEncrypt(dek, plaintext, aad)
	if err != nil {
		return nil, err
	}

	// 5. 组装信封：ephPubLen(1) ‖ ephPub(65) ‖ nonce(12) ‖ ct ‖ tag
	sealed := make([]byte, 0, 1+len(ephPubBytes)+len(nonce)+len(ciphertext))
	sealed = append(sealed, byte(len(ephPubBytes)))
	sealed = append(sealed, ephPubBytes...)
	sealed = append(sealed, nonce...)
	sealed = append(sealed, ciphertext...)

	return sealed, nil
}

// ECIESOpen 使用收件人 P-256 私钥解密 ECIES 信封，返回明文。
//
// recipientPriv 必须为 P-256 曲线的 *ecdsa.PrivateKey。
// sealed 必须为 ECIESSeal 输出格式，否则返回对应哨兵错误。
// aad 须与 Seal 时传入相同，否则返回 ErrECIESAuthFailed。
//
// 错误映射：
//   - 信封过短/ephPubLen 不匹配 → ErrECIESTooShort
//   - 临时公钥非法 → ErrECIESInvalidEphPub
//   - GCM 认证失败 → ErrECIESAuthFailed
func ECIESOpen(recipientPriv *ecdsa.PrivateKey, sealed, aad []byte) ([]byte, error) {
	// 校验密钥曲线
	if recipientPriv == nil || recipientPriv.PublicKey.Curve == nil {
		return nil, ErrECIESInvalidCurve
	}
	if recipientPriv.PublicKey.Curve != elliptic.P256() {
		return nil, ErrECIESInvalidCurve
	}

	// 校验信封最小长度
	if len(sealed) < eciesMinSealedLen {
		return nil, ErrECIESTooShort
	}

	// 1. 解析 ephPubLen 字段
	ephPubLen := int(sealed[0])
	if ephPubLen != eciesEphPubLen {
		return nil, ErrECIESTooShort
	}

	// 2. 解析临时公钥（65B）
	if len(sealed) < 1+ephPubLen {
		return nil, ErrECIESTooShort
	}
	ephPubBytes := sealed[1 : 1+ephPubLen]

	// 3. 解析 nonce（12B）
	nonceOffset := 1 + ephPubLen
	if len(sealed) < nonceOffset+eciesNonceLen {
		return nil, ErrECIESTooShort
	}
	nonce := sealed[nonceOffset : nonceOffset+eciesNonceLen]

	// 4. 剩余部分 = ciphertext ‖ tag
	ctOffset := nonceOffset + eciesNonceLen
	ctWithTag := sealed[ctOffset:]
	if len(ctWithTag) < eciesTagLen {
		return nil, ErrECIESTooShort
	}

	// 转换 ecdsa 私钥为 ecdh 私钥
	ecdhPriv, err := recipientPriv.ECDH()
	if err != nil {
		return nil, ErrECIESInvalidCurve
	}

	// 解析临时公钥
	ephPub, err := ecdh.P256().NewPublicKey(ephPubBytes)
	if err != nil {
		return nil, ErrECIESInvalidEphPub
	}

	// 5. ECDH 密钥协商
	shared, err := ecdhPriv.ECDH(ephPub)
	if err != nil {
		return nil, ErrECIESInvalidEphPub
	}
	defer func() {
		common.ZeroBytes(shared)
	}()

	// 6. HKDF-SHA256 派生 DEK
	dek, err := eciesDeriveKey(shared)
	if err != nil {
		return nil, err
	}
	defer func() {
		common.ZeroBytes(dek)
	}()

	// 7. AES-128-GCM 解密
	plaintext, err := eciesDecrypt(dek, nonce, ctWithTag, aad)
	if err != nil {
		return nil, ErrECIESAuthFailed
	}

	return plaintext, nil
}

// eciesDeriveKey 使用 HKDF-SHA256 从共享密钥派生 16B DEK。
func eciesDeriveKey(shared []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, shared, nil, eciesHKDFInfo, eciesDEKLen)
}

// eciesEncrypt 使用 AES-128-GCM 加密明文，返回 ciphertext ‖ tag 和 nonce。
func eciesEncrypt(dek, plaintext, aad []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	// 生成随机 nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}

	// GCM Seal 返回 nonce ‖ ciphertext ‖ tag，我们分离 nonce
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)
	return ciphertext, nonce, nil
}

// eciesDecrypt 使用 AES-128-GCM 解密密文，返回明文。
// ctWithTag = ciphertext ‖ tag(16B)
func eciesDecrypt(dek, nonce, ctWithTag, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// ctWithTag 必须至少有 tag 长度
	if len(ctWithTag) < gcm.Overhead() {
		return nil, ErrECIESTooShort
	}

	plaintext, err := gcm.Open(nil, nonce, ctWithTag, aad)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}