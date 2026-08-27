package envelope

import (
	"errors"
	"fmt"

	rootcrypto "github.com/charlienet/go-crypto"
	_ "github.com/charlienet/go-crypto/symmetric" // 注册对称引擎（NewCipher 依赖）
)

// gcx1 信封格式常量。
const (
	gcx1Magic     = "gcx1"                       // 4 字节魔数
	gcx1Version   = 0x01                         // 格式版本 v1（已冻结，仅兼容读取）
	gcx1VersionV2 = 0x02                         // 格式版本 v2：header 元数据纳入 GCM AAD 认证
	gcx1NonceLen  = 12                           // 固定 nonce 长度
	gcx1HeaderLen = 7                            // magic(4) + version(1) + algID(1) + nonceLen(1)
	gcx1MinLen    = gcx1HeaderLen + gcx1NonceLen // = 19，最小合法长度
	// gcx1TagLen gcx1 自身的 GCM 认证标签长度（16 字节，AES/SM4-GCM 标准标签长）。
	// 独立于 fsb1 的 TagSize 常量，避免 gcx1 格式的尺寸语义耦合到分块格式。
	gcx1TagLen = 16
)

// gcx1 信封的算法标识字节（自根包 alg.go 迁入，随信封格式归属本包）。
const (
	algIDSM4    byte = 0x01
	algIDAES128 byte = 0x02
	algIDAES192 byte = 0x03
	algIDAES256 byte = 0x04
	algIDDES    byte = 0x05
	algID3DES   byte = 0x06
)

// algorithmIDMap 将算法常量名映射到 gcx1 algID 字节。
var algorithmIDMap = map[rootcrypto.Algorithm]byte{
	rootcrypto.SM4:       algIDSM4,
	rootcrypto.AES128:    algIDAES128,
	rootcrypto.AES192:    algIDAES192,
	rootcrypto.AES256:    algIDAES256,
	rootcrypto.DES:       algIDDES,
	rootcrypto.TripleDES: algID3DES,
}

// idAlgorithmMap 将 gcx1 algID 字节映射回算法常量名。
var idAlgorithmMap = map[byte]rootcrypto.Algorithm{
	algIDSM4:    rootcrypto.SM4,
	algIDAES128: rootcrypto.AES128,
	algIDAES192: rootcrypto.AES192,
	algIDAES256: rootcrypto.AES256,
	algIDDES:    rootcrypto.DES,
	algID3DES:   rootcrypto.TripleDES,
}

var (
	errGcx1TooShort         = errors.New("gcx1: 密文过短，不足 19 字节")
	errGcx1MagicMismatch    = errors.New("gcx1: 魔数不匹配，非 gcx1 格式")
	errGcx1VersionMismatch  = errors.New("gcx1: 版本号不匹配")
	errGcx1NonceLenMismatch = errors.New("gcx1: nonce 长度不为 12")
	errGcx1UnknownAlgID     = errors.New("gcx1: 未知算法标识")
	errGcx1DESNotSupported  = errors.New(
		"DES/3DES 不支持 GCM 认证加密（块大小 8 字节），" +
			"如需兼容遗留数据请使用低层 API 的 CBC/CTR 模式",
	)
)

// buildGcx1MetaAAD 构造 v2 信封头部元数据区域（magic+version+algID+nonceLen，7 字节），
// 作为 GCM AAD 绑定，防止 header 元数据被篡改。nonce 由 GCM 认证天然绑定，无需重复纳入。
func buildGcx1MetaAAD(algID byte) []byte {
	aad := make([]byte, 0, gcx1HeaderLen)
	aad = append(aad, gcx1Magic...)
	aad = append(aad, gcx1VersionV2)
	aad = append(aad, algID)
	aad = append(aad, gcx1NonceLen)
	return aad
}

// Encrypt 使用指定算法和密钥加密明文，输出 gcx1 自描述信封格式。
// 固定使用 GCM 认证加密 + 随机 nonce。
// 总开销 35 字节（头 19 字节 + GCM tag 16 字节）。
//
// 支持的算法：SM4、AES-128、AES-192、AES-256。
// DES/3DES 因块大小为 8 字节无法使用 GCM，返回明确错误。
//
// 输出 v2 信封：header 元数据（magic/version/algID/nonceLen）纳入 GCM AAD，
// 防篡改；v1 信封仍可被 Decrypt 兼容读取。
func Encrypt(algorithm rootcrypto.Algorithm, key []byte, plaintext []byte) ([]byte, error) {
	if algorithm == rootcrypto.DES || algorithm == rootcrypto.TripleDES {
		return nil, errGcx1DESNotSupported
	}
	algID, ok := algorithmIDMap[algorithm]
	if !ok {
		return nil, fmt.Errorf("gcx1: 不支持的算法: %s", algorithm)
	}

	c, err := rootcrypto.NewCipher(algorithm.String(), key)
	if err != nil {
		return nil, err
	}
	// v2：header 元数据纳入 GCM AAD，防止 header 被篡改。
	// 使用 EmbedNonce + nil nonce：随机生成并嵌入，与 NewGCMWithRandomNonce 行为一致。
	gcm, err := c.NewGCM(nil, rootcrypto.WithAAD(buildGcx1MetaAAD(algID)), rootcrypto.EmbedNonce())
	if err != nil {
		return nil, err
	}

	sealed, err := gcm.Encrypt(plaintext)
	if err != nil {
		return nil, err
	}
	return buildGcx1(algID, sealed), nil
}

// EncryptWithAAD 使用指定算法和密钥加密明文，同时附加 AAD（额外认证数据）。
// AAD 不入信封，由调用方在解密时提供相同值。
// 输出 v2 信封：AAD = header 元数据 || 调用方 AAD。
func EncryptWithAAD(algorithm rootcrypto.Algorithm, key []byte, plaintext, aad []byte) ([]byte, error) {
	if algorithm == rootcrypto.DES || algorithm == rootcrypto.TripleDES {
		return nil, errGcx1DESNotSupported
	}
	algID, ok := algorithmIDMap[algorithm]
	if !ok {
		return nil, fmt.Errorf("gcx1: 不支持的算法: %s", algorithm)
	}

	c, err := rootcrypto.NewCipher(algorithm.String(), key)
	if err != nil {
		return nil, err
	}
	// v2：header 元数据 + 用户 AAD 共同纳入 GCM AAD。
	// 使用 EmbedNonce + nil nonce：随机生成并嵌入，与 NewGCMWithRandomNonce 行为一致。
	fullAAD := append(buildGcx1MetaAAD(algID), aad...)
	gcm, err := c.NewGCM(nil, rootcrypto.WithAAD(fullAAD), rootcrypto.EmbedNonce())
	if err != nil {
		return nil, err
	}

	sealed, err := gcm.Encrypt(plaintext)
	if err != nil {
		return nil, err
	}
	return buildGcx1(algID, sealed), nil
}

// buildGcx1 将 algID + sealed 数据组装为完整的 gcx1 信封（v2 版本号）。
// sealed 格式（由 NewGCMWithRandomNonce / embednonce=true 产生）：
//
//	nonce(12B) || ciphertext || tag(16B)
func buildGcx1(algID byte, sealed []byte) []byte {
	nonce := sealed[:gcx1NonceLen]
	payload := sealed[gcx1NonceLen:]

	envelope := make([]byte, 0, gcx1HeaderLen+len(sealed))
	envelope = append(envelope, gcx1Magic...)
	envelope = append(envelope, gcx1VersionV2)
	envelope = append(envelope, algID)
	envelope = append(envelope, gcx1NonceLen)
	envelope = append(envelope, nonce...)
	envelope = append(envelope, payload...)
	return envelope
}

// Decrypt 解密 gcx1 信封格式的密文。
// 校验顺序：长度 → 魔数 → 版本 → nonceLen → algID → GCM 认证解密。
func Decrypt(key []byte, envelope []byte) ([]byte, error) {
	return decryptInternal(key, envelope, nil)
}

// DecryptWithAAD 解密 gcx1 信封格式的密文，同时验证 AAD。
// 调用方必须提供加密时使用的相同 AAD，否则 GCM 认证失败。
func DecryptWithAAD(key []byte, envelope, aad []byte) ([]byte, error) {
	return decryptInternal(key, envelope, aad)
}

func decryptInternal(key, envelope, aad []byte) ([]byte, error) {
	if len(envelope) < gcx1MinLen {
		return nil, errGcx1TooShort
	}
	if string(envelope[:4]) != gcx1Magic {
		return nil, errGcx1MagicMismatch
	}
	// 版本分支：v1（冻结格式，兼容读取）与 v2（header 入 AAD）均支持，其余版本拒绝
	version := envelope[4]
	if version != gcx1Version && version != gcx1VersionV2 {
		return nil, errGcx1VersionMismatch
	}
	if envelope[6] != gcx1NonceLen {
		return nil, errGcx1NonceLenMismatch
	}

	algID := envelope[5]
	alg, ok := idAlgorithmMap[algID]
	if !ok {
		return nil, errGcx1UnknownAlgID
	}
	if alg == rootcrypto.DES || alg == rootcrypto.TripleDES {
		return nil, errGcx1DESNotSupported
	}

	nonce := envelope[gcx1HeaderLen : gcx1HeaderLen+gcx1NonceLen]
	ciphertext := envelope[gcx1HeaderLen+gcx1NonceLen:]

	c, err := rootcrypto.NewCipher(alg.String(), key)
	if err != nil {
		return nil, err
	}

	// 构造 AAD：v2 时 header 元数据纳入 GCM AAD 认证（v1 保持无 AAD 的旧行为）；
	// 用户 AAD（若有）始终追加在末尾。
	var gcmAAD []byte
	if version == gcx1VersionV2 {
		gcmAAD = buildGcx1MetaAAD(algID)
	}
	if len(aad) > 0 {
		gcmAAD = append(append([]byte(nil), gcmAAD...), aad...)
	}
	var opts []rootcrypto.Option
	if len(gcmAAD) > 0 {
		opts = append(opts, rootcrypto.WithAAD(gcmAAD))
	}
	gcm, err := c.NewGCM(nonce, opts...)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Decrypt(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("gcx1: 解密失败: %w", err)
	}
	return plaintext, nil
}
