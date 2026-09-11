package envelope

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"

	"github.com/cloudflare/circl/hpke"
)

// HPKESuite 标识 HPKE cipher suite（RFC 9180 §7）。
// 字段已导出，允许外部构造自定义 suite（需确保 KEM/KDF/AEAD 组合有效）。
type HPKESuite struct {
	KEM  uint16 // DHKEM_X25519_HKDF_SHA256 = 0x0020
	KDF  uint16 // HKDF_SHA256              = 0x0001
	AEAD uint16 // AES_128_GCM=0x0001; AES_256_GCM=0x0002
}

// 预定义 HPKE cipher suites（RFC 9180 §7.1）。
var (
	// HPKE_X25519_HKDF_SHA256_AES_128_GCM 对应 RFC 9180 §A.1 测试向量。
	HPKE_X25519_HKDF_SHA256_AES_128_GCM = HPKESuite{0x0020, 0x0001, 0x0001}
	// HPKE_X25519_HKDF_SHA256_AES_256_GCM 提供 256 位对称密钥强度。
	HPKE_X25519_HKDF_SHA256_AES_256_GCM = HPKESuite{0x0020, 0x0001, 0x0002}
)

var (
	// ErrHPKEUnsupportedSuite 不支持的 cipher suite。
	ErrHPKEUnsupportedSuite = errors.New("hpke: unsupported cipher suite")
	// ErrHPKEUnsupportedKey 不支持的密钥类型（必须为 X25519）。
	ErrHPKEUnsupportedKey = errors.New("hpke: unsupported key type (must be X25519)")
	// ErrHPKEOpenFailed HPKE 开包失败。
	ErrHPKEOpenFailed = errors.New("hpke: opening failed")
)

// hpkeResolveSuite 将 HPKESuite 转换为 CIRCL hpke.Suite。
// 当前仅支持 X25519 KEM + HKDF-SHA256 KDF + AES-128/256-GCM AEAD。
func hpkeResolveSuite(suite HPKESuite) (hpke.Suite, error) {
	if suite.KEM != 0x0020 {
		return hpke.Suite{}, ErrHPKEUnsupportedSuite
	}
	if suite.KDF != 0x0001 {
		return hpke.Suite{}, ErrHPKEUnsupportedSuite
	}
	switch suite.AEAD {
	case 0x0001:
		return hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM), nil
	case 0x0002:
		return hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES256GCM), nil
	default:
		return hpke.Suite{}, ErrHPKEUnsupportedSuite
	}
}

// HPKESeal Base 模式密封。
//
// 输出: enc(32B X25519 公钥) ‖ ciphertext
//
// 安全模型：HPKE Base 模式（RFC 9180 §5.1），发送方临时密钥，接收方静态公钥。
// 提供前向保密（ephemeral-ephemeral DH）但不提供发送方认证（sender authentication）。
// 每次调用生成新的临时密钥对，密文不可链接。
//
// 参数约束：
//   - recipientPub 必须为 *ecdh.PublicKey 且曲线为 X25519
//   - suite 必须为 HPKE_X25519_HKDF_SHA256_AES_128_GCM 或 HPKE_X25519_HKDF_SHA256_AES_256_GCM
//   - info 用于密钥调度上下文绑定，可为 nil（应用层应传递协议级上下文以防止跨协议攻击）
func HPKESeal(suite HPKESuite, recipientPub *ecdh.PublicKey, plaintext, info []byte) (enc, ciphertext []byte, err error) {
	// 解析 suite
	hpkeSuite, err := hpkeResolveSuite(suite)
	if err != nil {
		return nil, nil, err
	}

	// 校验密钥类型
	if recipientPub == nil || recipientPub.Curve() != ecdh.X25519() {
		return nil, nil, ErrHPKEUnsupportedKey
	}

	// 转换公钥：ecdh.PublicKey -> circl kem.PublicKey
	kemScheme := hpke.KEM_X25519_HKDF_SHA256.Scheme()
	pkR, err := kemScheme.UnmarshalBinaryPublicKey(recipientPub.Bytes())
	if err != nil {
		return nil, nil, err
	}

	// 创建发送方
	sender, err := hpkeSuite.NewSender(pkR, info)
	if err != nil {
		return nil, nil, err
	}

	// Setup 生成临时密钥对并封装共享密钥
	enc, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// 加密明文（aad=nil）
	ciphertext, err = sealer.Seal(plaintext, nil)
	if err != nil {
		return nil, nil, err
	}

	return enc, ciphertext, nil
}

// HPKEOpen Base 模式打开。
//
// 安全模型：对应 HPKESeal，接收方使用静态私钥解密。
// 验证密文完整性（AEAD 认证），失败返回哨兵错误 ErrHPKEOpenFailed。
//
// 参数约束：
//   - recipientPriv 必须为 *ecdh.PrivateKey 且曲线为 X25519
//   - enc 必须为发送方输出的临时公钥（32 字节）
//   - ciphertext 必须为发送方输出的密文
//   - info 必须与密封时使用的 info 一致
//   - suite 必须为 HPKE_X25519_HKDF_SHA256_AES_128_GCM 或 HPKE_X25519_HKDF_SHA256_AES_256_GCM
func HPKEOpen(suite HPKESuite, recipientPriv *ecdh.PrivateKey, enc, ciphertext, info []byte) ([]byte, error) {
	// 解析 suite
	hpkeSuite, err := hpkeResolveSuite(suite)
	if err != nil {
		return nil, err
	}

	// 校验密钥类型
	if recipientPriv == nil || recipientPriv.Curve() != ecdh.X25519() {
		return nil, ErrHPKEUnsupportedKey
	}

	// 转换私钥：ecdh.PrivateKey -> circl kem.PrivateKey
	kemScheme := hpke.KEM_X25519_HKDF_SHA256.Scheme()
	skR, err := kemScheme.UnmarshalBinaryPrivateKey(recipientPriv.Bytes())
	if err != nil {
		return nil, err
	}

	// 创建接收方
	receiver, err := hpkeSuite.NewReceiver(skR, info)
	if err != nil {
		return nil, err
	}

	// Setup 使用封装的密钥（enc）恢复共享密钥
	opener, err := receiver.Setup(enc)
	if err != nil {
		return nil, err
	}

	// 解密密文（aad=nil）
	plaintext, err := opener.Open(ciphertext, nil)
	if err != nil {
		// 统一返回哨兵错误，避免暴露具体失败原因（抗 oracle）
		return nil, ErrHPKEOpenFailed
	}

	return plaintext, nil
}