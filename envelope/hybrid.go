package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	rootcrypto "github.com/charlienet/go-crypto"
)

// hyb1 数字信封：KEM + AEAD 混合加密（"公钥信封"，自描述单条 []byte）。
//
// 定位：给公钥持有者加密（大）数据的一站式 API。内部自动完成 KEM
// （密钥封装：RSA-OAEP 或 X25519 临时-静态 ECDH）与 AEAD（DEK 对称
// GCM 加密 payload），杜绝调用方手拼 RSA-OAEP + AES。
//
// 字节布局（冻结格式，多字节字段均为大端序）：
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
// payload GCM 的 AAD = 完整头部（7B）‖ 用户 AAD：头部整体入 AAD，
// 参照 gcx1 v2 / fsb2 的 header 入 AAD 防篡改做法，篡改头部任一字节
// （含 KEM/算法混淆）都被 payload GCM 认证拒绝。
//
// X25519 路径 wrap：HKDF-SHA256(shared, salt=头部 7B, info="GCHY-hyb1-dek")
// → 32B wrap key → AES-256-GCM(wrap key, 12B 随机 nonce) 加密 DEK。
// RSA 路径：随机 DEK 直接 OAEP(SHA-256) 加密，无独立 wrap 层
// （nonce 段与 ephPub 段长度均为 0，布局仍保留长度字段保证解析统一）。
const (
	hyb1Magic      = "GCHY"
	hyb1Version    = 0x00          // 版本 0：首版冻结
	hyb1HeaderLen  = 4 + 1 + 1 + 1 // magic(4)+version(1)+kemID(1)+payloadAlgID(1) = 7
	hyb1LenFieldSz = 2             // kem 段每个长度字段（BE16）

	// KEM 标识字节。
	hyb1KemRSA    byte = 0x01 // RSA-OAEP(SHA-256)
	hyb1KemX25519 byte = 0x02 // X25519 临时-静态 ECDH + HKDF 派生 wrap key

	// payload 算法标识字节。hyb1 独立 ID 空间（紧凑编号，0x01/0x02）：
	// SM4 与 fsb2AlgID 表（fsb2AlgIDSM4=0x01）语义对齐；AES-256 压缩为 0x02，
	// 不沿用 fsb2 的 0x04（fsb2 需区分 AES-128/192/256 三档，hyb1 仅启用两档
	// 且由 DEK 长度自描述，无需为 128/192 预留条目）。
	hyb1PayloadSM4    byte = 0x01
	hyb1PayloadAES256 byte = 0x02

	hyb1NonceLen     = 12 // GCM nonce 长度（wrap 与 payload 恒为 12）
	hyb1TagLen       = 16 // GCM 认证标签长度
	hyb1X25519PubLen = 32 // X25519 公钥长度
	hyb1WrapKeyLen   = 32 // HKDF 派生 wrap key 长度（AES-256）
	hyb1AES256KeyLen = 32 // AES-256-GCM 的 DEK 长度
	hyb1SM4KeyLen    = 16 // SM4-GCM 的 DEK 长度

	// hyb1MinPayloadLen payload 段最小长度：nonce(12) + tag(16)（空明文）。
	hyb1MinPayloadLen = hyb1NonceLen + hyb1TagLen
)

// hyb1HKDFInfo X25519 路径 HKDF 的 info 参数，域名分离防与库内其他
// HKDF 用途串义（RFC 5869 info 只做上下文区分，非秘密）。
const hyb1HKDFInfo = "GCHY-hyb1-dek"

var (
	// —— hyb1 哨兵错误 ——
	// ErrHybridTooShort 数据长度不足头部（7 字节）。
	ErrHybridTooShort = errors.New("hyb1: sealed data too short")
	// ErrHybridMagicMismatch 魔数不符，非 GCHY 信封。
	ErrHybridMagicMismatch = errors.New("hyb1: magic mismatch, not a GCHY envelope")
	// ErrHybridVersionMismatch 版本号不受支持。
	ErrHybridVersionMismatch = errors.New("hyb1: unsupported envelope version")
	// ErrHybridUnknownKEM 头部声明的 KEM 标识未注册。
	ErrHybridUnknownKEM = errors.New("hyb1: unknown KEM id")
	// ErrHybridUnknownPayload 头部声明的 payload 算法标识未注册。
	ErrHybridUnknownPayload = errors.New("hyb1: unknown payload algorithm id")
	// ErrHybridBadLengths kem 段长度字段非法（越界/截断/与 KEM 预期不符）。
	ErrHybridBadLengths = errors.New("hyb1: malformed length fields or truncated sections")
	// ErrHybridBadEphKey X25519 临时公钥非法（长度必须恰为 32 字节，或内容不可用）。
	ErrHybridBadEphKey = errors.New("hyb1: invalid ephemeral key (X25519 requires exactly 32 bytes)")
	// ErrHybridKeyTooWeak RSA 公钥低于 2048-bit（对齐 asym/rsa.go 弱密钥策略）。
	ErrHybridKeyTooWeak = errors.New("hyb1: RSA public key too weak")
	// ErrHybridUnsupportedKey 密钥类型不受支持（未知类型/nil/非 X25519 曲线 ecdh 密钥等）。
	ErrHybridUnsupportedKey = errors.New("hyb1: unsupported key type")
	// ErrHybridKeyMismatch 私钥类型与信封 kemID 不匹配（如 RSA 私钥解 X25519 信封）。
	ErrHybridKeyMismatch = errors.New("hyb1: private key type does not match the envelope KEM")
	// ErrHybridRSAOpenFailed RSA 路径所有解密语义失败统一返回该哨兵
	// （OAEP 解密失败、DEK 长度不符、payload GCM 认证失败）。
	//
	// 统一理由（抗 oracle）：RSA-OAEP 为唯一包装层（无独立 wrap GCM），
	// 若将"encDEK 非本密钥可解"与"payload 被篡改/密钥错误"区分报错，
	// 攻击者经响应差异即可逐条探测收件人与密文有效性；统一使 RSA 路径
	// 对外表现为单一失败黑盒，OAEP 的 IND-CCA2 属性才能完整传递。
	ErrHybridRSAOpenFailed = errors.New("hyb1: RSA opening failed")
	// ErrHybridAuthFailed X25519 路径认证失败统一哨兵（wrap GCM 开包失败与
	// payload GCM 认证失败不可区分）：ephPub 与私钥不匹配与数据被篡改
	// 对外一致，避免暴露"收件人探测"信标。
	ErrHybridAuthFailed = errors.New("hyb1: authentication failed")
)

// hybridKeyKind 密钥分类（决定使用哪个 KEM 路径）。
type hybridKeyKind int

const (
	hybridKeyUnknown hybridKeyKind = iota
	hybridKeyRSA
	hybridKeyX25519
)

// hybridPubKind 分类公钥类型：RSA / X25519。X25519 公钥的标准表示为
// *ecdh.PublicKey 且必须为 X25519 曲线（曲线对象身份比较，区分 NIST 曲线；
// x/crypto/x25519 旧式 []byte 包装已在上游移除，不再支持）。
// nil 指针、非法曲线归 hybridKeyUnknown。
func hybridPubKind(pub any) hybridKeyKind {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if k == nil || k.N == nil {
			return hybridKeyUnknown
		}
		return hybridKeyRSA
	case *ecdh.PublicKey:
		if k.Curve() != ecdh.X25519() {
			return hybridKeyUnknown
		}
		return hybridKeyX25519
	default:
		return hybridKeyUnknown
	}
}

// hybridPrivKind 分类私钥类型，规则与 hybridPubKind 对称。
func hybridPrivKind(priv any) hybridKeyKind {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		if k == nil || k.N == nil {
			return hybridKeyUnknown
		}
		return hybridKeyRSA
	case *ecdh.PrivateKey:
		if k.Curve() != ecdh.X25519() {
			return hybridKeyUnknown
		}
		return hybridKeyX25519
	default:
		return hybridKeyUnknown
	}
}

// hybridDEKLen 返回 payload 算法的 DEK 长度；未知算法 ID 返回 0。
func hybridDEKLen(payloadAlgID byte) int {
	switch payloadAlgID {
	case hyb1PayloadSM4:
		return hyb1SM4KeyLen
	case hyb1PayloadAES256:
		return hyb1AES256KeyLen
	default:
		return 0
	}
}

// hyb1PayloadAlgName payloadAlgID → 对称注册键（rootcrypto.NewCipher 消费）。
func hyb1PayloadAlgName(payloadAlgID byte) (string, error) {
	switch payloadAlgID {
	case hyb1PayloadSM4:
		return rootcrypto.AlgorithmSM4, nil
	case hyb1PayloadAES256:
		return rootcrypto.AlgorithmAES256, nil
	default:
		return "", ErrHybridUnknownPayload
	}
}

// buildHyb1Header 构造 7 字节头部：magic ‖ version ‖ kemID ‖ payloadAlgID。
func buildHyb1Header(kemID, payloadAlgID byte) []byte {
	h := make([]byte, hyb1HeaderLen)
	copy(h, hyb1Magic)
	h[4] = hyb1Version
	h[5] = kemID
	h[6] = payloadAlgID
	return h
}

// buildHyb1PayloadAAD 构造 payload GCM AAD：完整头部（7B）‖ 用户 AAD。
// 头部整体入 AAD（参照 gcx1 v2 / fsb2），篡改头部任一字节被 GCM 认证拒绝。
func buildHyb1PayloadAAD(header, userAAD []byte) []byte {
	aad := make([]byte, 0, len(header)+len(userAAD))
	aad = append(aad, header...)
	aad = append(aad, userAAD...)
	return aad
}

// appendLenField 追加大端 2B 长度字段 + 数据。
func appendLenField(dst, data []byte) []byte {
	var l [hyb1LenFieldSz]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(data)))
	dst = append(dst, l[:]...)
	return append(dst, data...)
}

// buildHyb1Sealed 组装完整信封：header ‖ kem 段（3×(2B 长度+数据)）‖ payload。
func buildHyb1Sealed(header, ephPub, wrapNonce, encDEK, payload []byte) []byte {
	sealed := make([]byte, 0,
		hyb1HeaderLen+3*hyb1LenFieldSz+len(ephPub)+len(wrapNonce)+len(encDEK)+len(payload))
	sealed = append(sealed, header...)
	sealed = appendLenField(sealed, ephPub)
	sealed = appendLenField(sealed, wrapNonce)
	sealed = appendLenField(sealed, encDEK)
	return append(sealed, payload...)
}

// generateHyb1DEK 按 payload 算法生成随机 DEK（crypto/rand）。
func generateHyb1DEK(payloadAlgID byte) ([]byte, error) {
	dekLen := hybridDEKLen(payloadAlgID)
	if dekLen == 0 {
		return nil, ErrHybridUnknownPayload
	}
	dek := make([]byte, dekLen)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, fmt.Errorf("hyb1: generate DEK: %w", err)
	}
	return dek, nil
}

// sealHyb1Payload 用 DEK 对明文做 GCM 认证加密，输出 nonce(12) ‖ ct ‖ tag。
func sealHyb1Payload(payloadAlgID byte, dek, header, plaintext, userAAD []byte) ([]byte, error) {
	algName, err := hyb1PayloadAlgName(payloadAlgID)
	if err != nil {
		return nil, err
	}
	c, err := rootcrypto.NewCipher(algName, dek)
	if err != nil {
		return nil, fmt.Errorf("hyb1: %w", err)
	}
	gcm, err := cipher.NewGCM(c.Block())
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("hyb1: generate payload nonce: %w", err)
	}
	sealed := gcm.Seal(nil, nonce, plaintext, buildHyb1PayloadAAD(header, userAAD))
	out := make([]byte, 0, len(nonce)+len(sealed))
	out = append(out, nonce...)
	return append(out, sealed...), nil
}

// openHyb1Payload 校验并解密 payload 段（nonce ‖ ct ‖ tag），
// AAD 校验失败返回 GCM 认证错误（由调用方归类到统一哨兵）。
func openHyb1Payload(payloadAlgID byte, dek, header, payload, userAAD []byte) ([]byte, error) {
	if len(payload) < hyb1MinPayloadLen {
		return nil, ErrHybridBadLengths
	}
	algName, err := hyb1PayloadAlgName(payloadAlgID)
	if err != nil {
		return nil, err
	}
	c, err := rootcrypto.NewCipher(algName, dek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(c.Block())
	if err != nil {
		return nil, err
	}
	nonce, ct := payload[:gcm.NonceSize()], payload[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, buildHyb1PayloadAAD(header, userAAD))
}

// Seal 使用收件人公钥加密明文，输出自描述 hyb1 数字信封（[]byte）。
//
// recipientPub 支持：
//   - *rsa.PublicKey：RSA-OAEP(SHA-256) 路径（DEK 直接 OAEP 加密）；
//     低于 2048-bit 的弱公钥被拒绝（对齐 asym/rsa.go 弱密钥策略措辞）。
//   - *ecdh.PublicKey：须为 X25519 曲线（crypto/ecdh 下 X25519 公钥的
//     标准表示；x/crypto/x25519 旧式 []byte 包装已在上游移除，不支持）。
//
// payload 算法固定 AES-256-GCM（安全默认，DEK 32B）。hyb1 亦定义
// SM4-GCM（payloadAlgID=0x01）用于兼容解密与低算力场景的后续扩展——
// 当前版本 Seal 不暴露算法选择，SM4 信封由内部密封函数构造（见测试）。
// aad 参与 payload GCM 认证但不入信封，Open 侧必须提供相同值。
func Seal(recipientPub any, plaintext, aad []byte) ([]byte, error) {
	return sealInternal(recipientPub, plaintext, aad, hyb1PayloadAES256)
}

// sealInternal 按显式 payload 算法密封（Seal 固定 AES-256，测试与未来
// 扩展经此选择 SM4）。
func sealInternal(recipientPub any, plaintext, aad []byte, payloadAlgID byte) ([]byte, error) {
	switch hybridPubKind(recipientPub) {
	case hybridKeyRSA:
		return sealHyb1RSA(recipientPub.(*rsa.PublicKey), plaintext, aad, payloadAlgID)
	case hybridKeyX25519:
		return sealHyb1X25519(recipientPub, plaintext, aad, payloadAlgID)
	default:
		return nil, ErrHybridUnsupportedKey
	}
}

// sealHyb1RSA RSA-OAEP 路径：随机 DEK 直接 OAEP(SHA-256) 加密后封装。
func sealHyb1RSA(pub *rsa.PublicKey, plaintext, aad []byte, payloadAlgID byte) ([]byte, error) {
	if pub.N.BitLen() < 2048 {
		return nil, fmt.Errorf("%w: RSA public key too weak: %d bits, minimum required is 2048 bits",
			ErrHybridKeyTooWeak, pub.N.BitLen())
	}
	header := buildHyb1Header(hyb1KemRSA, payloadAlgID)

	dek, err := generateHyb1DEK(payloadAlgID)
	if err != nil {
		return nil, err
	}
	// OAEP 使用 SHA-256、label 为空（同 asym/rsa.go Encrypt 惯例）。
	// RSA 路径无独立 wrap 层：ephPub 段与 nonce 段均为空。
	encDEK, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, dek, []byte{})
	if err != nil {
		return nil, fmt.Errorf("hyb1: RSA-OAEP: %w", err)
	}
	payload, err := sealHyb1Payload(payloadAlgID, dek, header, plaintext, aad)
	if err != nil {
		return nil, err
	}
	return buildHyb1Sealed(header, nil, nil, encDEK, payload), nil
}

// sealHyb1X25519 X25519 临时-静态 ECDH 路径。
func sealHyb1X25519(recipientPub any, plaintext, aad []byte, payloadAlgID byte) ([]byte, error) {
	// hybridPubKind 已在 sealInternal 校验为 X25519 曲线，此处直接断言。
	ecdhPub := recipientPub.(*ecdh.PublicKey)
	header := buildHyb1Header(hyb1KemX25519, payloadAlgID)

	// 每封信封生成全新 ephemeral 密钥对（前向保密）。
	ephPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("hyb1: generate ephemeral key: %w", err)
	}
	shared, err := ephPriv.ECDH(ecdhPub)
	if err != nil {
		return nil, fmt.Errorf("hyb1: ECDH: %w", err)
	}

	// HKDF-SHA256 派生 wrap key：salt=头部整体（绑定 kemID/payloadAlgID/版本），
	// info 域名分离防跨用途派生（agreement 包导出的是原始共享密钥，
	// 调用方即使误用它也得不到与信封兼容的 wrap key）。
	wrapKey, err := hkdf.Key(sha256.New, shared, header, hyb1HKDFInfo, hyb1WrapKeyLen)
	if err != nil {
		return nil, fmt.Errorf("hyb1: derive wrap key: %w", err)
	}

	dek, err := generateHyb1DEK(payloadAlgID)
	if err != nil {
		return nil, err
	}

	// AES-256-GCM 包装 DEK。wrap 层 AAD 为空：DEK 完整性由 wrap GCM tag
	// 保证，信封整体篡改由 payload 层 AAD=header 认证兜底。
	block, err := aes.NewCipher(wrapKey) // wrapKey 恒 32B（AES-256），仅防御性接收错误
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	wrapNonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, wrapNonce); err != nil {
		return nil, fmt.Errorf("hyb1: generate wrap nonce: %w", err)
	}
	encDEK := gcm.Seal(nil, wrapNonce, dek, nil)

	payload, err := sealHyb1Payload(payloadAlgID, dek, header, plaintext, aad)
	if err != nil {
		return nil, err
	}
	return buildHyb1Sealed(header, ephPriv.PublicKey().Bytes(), wrapNonce, encDEK, payload), nil
}

// Open 使用收件人私钥解密 hyb1 信封，返回明文。
//
// recipientPriv 支持 *rsa.PrivateKey 与 *ecdh.PrivateKey（X25519 曲线）。
// aad 必须与 Seal 时一致。
//
// 校验顺序：长度 → magic → version → kemID/payloadAlgID 表 → kem 段长度
// 字段 → 密钥类型预检 → KEM 解出 DEK → payload GCM 认证解密。任一头部
// 或长度字段被篡改都在前置校验或 payload GCM AAD（header 入 AAD）处拒绝。
//
// 失败归类：结构/格式类错误返回对应哨兵（ErrHybridBadLengths 等）；
// RSA 路径全部解密语义失败统一 ErrHybridRSAOpenFailed、X25519 路径统一
// ErrHybridAuthFailed（见哨兵注释的抗 oracle 理由）。
func Open(recipientPriv any, sealed, aad []byte) ([]byte, error) {
	if len(sealed) < hyb1HeaderLen {
		return nil, ErrHybridTooShort
	}
	if string(sealed[:4]) != hyb1Magic {
		return nil, ErrHybridMagicMismatch
	}
	if sealed[4] != hyb1Version {
		return nil, ErrHybridVersionMismatch
	}
	kemID, payloadAlgID := sealed[5], sealed[6]
	switch kemID {
	case hyb1KemRSA, hyb1KemX25519:
	default:
		return nil, ErrHybridUnknownKEM
	}
	if hybridDEKLen(payloadAlgID) == 0 {
		return nil, ErrHybridUnknownPayload
	}

	// 解析 kem 段：3 个 2B BE 长度字段 + 对应数据。
	rest := sealed[hyb1HeaderLen:]
	o := 0
	readLenField := func() (int, bool) {
		if len(rest[o:]) < hyb1LenFieldSz {
			return 0, false
		}
		n := int(binary.BigEndian.Uint16(rest[o:]))
		o += hyb1LenFieldSz
		return n, true
	}
	ephPubLen, ok := readLenField()
	if !ok {
		return nil, ErrHybridBadLengths
	}
	if o+ephPubLen > len(rest) {
		return nil, ErrHybridBadLengths
	}
	ephPub := rest[o : o+ephPubLen]
	o += ephPubLen
	wrapNonceLen, ok := readLenField()
	if !ok {
		return nil, ErrHybridBadLengths
	}
	if o+wrapNonceLen > len(rest) {
		return nil, ErrHybridBadLengths
	}
	wrapNonce := rest[o : o+wrapNonceLen]
	o += wrapNonceLen
	encDEKLen, ok := readLenField()
	if !ok {
		return nil, ErrHybridBadLengths
	}
	if o+encDEKLen > len(rest) {
		return nil, ErrHybridBadLengths
	}
	encDEK := rest[o : o+encDEKLen]
	o += encDEKLen
	payload := rest[o:]
	if len(payload) < hyb1MinPayloadLen {
		return nil, ErrHybridBadLengths
	}

	// 密钥类型预检（调用方本地错误，快速失败；不属 oracle 面）。
	privKind := hybridPrivKind(recipientPriv)
	if privKind == hybridKeyUnknown {
		return nil, ErrHybridUnsupportedKey
	}
	kemMatch := (kemID == hyb1KemRSA && privKind == hybridKeyRSA) ||
		(kemID == hyb1KemX25519 && privKind == hybridKeyX25519)
	if !kemMatch {
		return nil, ErrHybridKeyMismatch
	}

	header := sealed[:hyb1HeaderLen]
	dekLen := hybridDEKLen(payloadAlgID)

	var dek []byte
	switch kemID {
	case hyb1KemRSA:
		// ephPub 段与 nonce 段必须为空（RSA 无独立 wrap 层）。
		if ephPubLen != 0 || wrapNonceLen != 0 {
			return nil, ErrHybridBadLengths
		}
		dek, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, recipientPriv.(*rsa.PrivateKey), encDEK, []byte{})
		if err != nil {
			return nil, ErrHybridRSAOpenFailed
		}
		// 防御：解出的 DEK 长度必须与 payload 算法匹配（正常 Seal 恒成立）。
		if len(dek) != dekLen {
			return nil, ErrHybridRSAOpenFailed
		}
		plaintext, err := openHyb1Payload(payloadAlgID, dek, header, payload, aad)
		if err != nil {
			// 统一错误：区分 payload 认证失败与 OAEP 失败会暴露 oracle 信标。
			return nil, ErrHybridRSAOpenFailed
		}
		return plaintext, nil

	case hyb1KemX25519:
		if ephPubLen != hyb1X25519PubLen {
			return nil, ErrHybridBadEphKey
		}
		if wrapNonceLen != hyb1NonceLen {
			return nil, ErrHybridBadLengths
		}
		// hybridPrivKind 已在上方预检为 X25519 曲线，此处直接断言。
		priv := recipientPriv.(*ecdh.PrivateKey)
		ephPubKey, err := ecdh.X25519().NewPublicKey(ephPub)
		if err != nil {
			return nil, ErrHybridBadEphKey
		}
		shared, err := priv.ECDH(ephPubKey)
		if err != nil {
			// 低阶点/全零共享：对外与认证失败一致，不泄露私钥结构信息。
			return nil, ErrHybridAuthFailed
		}
		wrapKey, err := hkdf.Key(sha256.New, shared, header, hyb1HKDFInfo, hyb1WrapKeyLen)
		if err != nil {
			return nil, fmt.Errorf("hyb1: derive wrap key: %w", err)
		}
		block, err := aes.NewCipher(wrapKey) // wrapKey 恒 32B（AES-256），仅防御性接收错误
		if err != nil {
			return nil, err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		dek, err = gcm.Open(nil, wrapNonce, encDEK, nil)
		if err != nil {
			return nil, ErrHybridAuthFailed
		}
		if len(dek) != dekLen {
			return nil, ErrHybridAuthFailed
		}
		plaintext, err := openHyb1Payload(payloadAlgID, dek, header, payload, aad)
		if err != nil {
			return nil, ErrHybridAuthFailed
		}
		return plaintext, nil
	}
	// kemID 已在上方表校验拦截，不可达。
	return nil, ErrHybridUnknownKEM
}
