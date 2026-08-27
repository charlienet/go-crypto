package crypto

import (
	"bytes"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"

	"github.com/charlienet/go-utils/bytesconv"
	"github.com/charlienet/go-crypto/crypto/common"
)

// ErrCiphertextNotAligned 密文长度不是块大小整数倍时返回的统一错误。
// 错误消息刻意不含填充细节，避免成为 padding oracle 攻击的判据。
var ErrCiphertextNotAligned = errors.New("ciphertext length must be a multiple of block size")

// ErrCiphertextTooShort 密文长度不足以容纳嵌入前缀（nonce/IV/计数器）时返回的统一错误。
var ErrCiphertextTooShort = errors.New("ciphertext too short")

// ErrInvalidPadding 填充校验失败的统一哨兵错误。
// 所有失败分支返回同一错误、错误消息不含任何细节，
// 避免攻击者通过不同错误消息区分填充错误类型（padding oracle 判据）。
var ErrInvalidPadding = errors.New("invalid padding")

// ErrInvalidKeyLength 密钥长度与算法要求不匹配时返回的统一哨兵错误。
// 错误消息附带长度细节（不敏感），供 errors.Is 判定。
var ErrInvalidKeyLength = errors.New("crypto: invalid key length")

// Padding 填充模式接口
type Padding interface {
	Padding(blockSize int, src []byte) ([]byte, error)
	UnPadding(blockSize int, src []byte) ([]byte, error)
}

// PKCS7 PKCS7 填充模式（默认填充，常量时间校验 + ErrInvalidPadding 哨兵）。
type PKCS7 struct{}

func (p PKCS7) Padding(blockSize int, src []byte) ([]byte, error) {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...), nil
}

func (p PKCS7) UnPadding(blockSize int, src []byte) ([]byte, error) {
	length := len(src)
	if length == 0 {
		return nil, ErrInvalidPadding
	}
	unpadding := int(src[length-1])
	if unpadding > blockSize || unpadding == 0 {
		return nil, ErrInvalidPadding
	}

	if length < unpadding {
		return nil, ErrInvalidPadding
	}

	pad := src[len(src)-unpadding:]
	// 常量时间校验：累计异或全部填充字节后统一判断，
	// 避免逐字节早退导致填充错误位置成为可观察的时序差异（padding oracle 判据）。
	bad := 0
	for i := 0; i < unpadding; i++ {
		bad |= int(pad[i]) ^ unpadding
	}
	if bad != 0 {
		return nil, ErrInvalidPadding
	}

	return src[:(length - unpadding)], nil
}

// ZeroPadding 零填充模式。
//
// 警告：仅适用于不以 0x00 结尾的文本或定长数据。UnPadding 会无条件剥离尾部
// 0x00 字节，因此以 0x00 结尾的二进制明文会在往返后静默损坏，且无 MAC 可检测。
// 二进制数据请使用 PKCS7 等自描述填充；新代码禁用本模式。
type ZeroPadding struct{}

func (p ZeroPadding) Padding(blockSize int, src []byte) ([]byte, error) {
	padding := blockSize - len(src)%blockSize
	if padding == blockSize {
		padding = 0
	}
	if padding > 0 {
		padtext := bytes.Repeat([]byte{0}, padding)
		return append(src, padtext...), nil
	}
	// 全对齐时返回独立拷贝，避免与输入共享底层数组：
	// 调用方后续修改返回值（或输入）不应污染另一方。
	return append([]byte(nil), src...), nil
}

func (p ZeroPadding) UnPadding(blockSize int, src []byte) ([]byte, error) {
	// 从末尾去除所有 0x00 字节
	end := len(src) - 1
	for end >= 0 && src[end] == 0 {
		end--
	}
	return src[:end+1], nil
}

// NoPadding 无填充模式。
//
// 注意：Padding/UnPadding 直接返回输入切片本身（与调用方共享底层数组），
// 调用方修改返回值会同步影响输入；如需独立副本请自行拷贝。
type NoPadding struct{}

func (p NoPadding) Padding(blockSize int, src []byte) ([]byte, error) {
	if len(src)%blockSize != 0 {
		return nil, fmt.Errorf("data length must be multiple of block size %d", blockSize)
	}
	return src, nil
}

func (p NoPadding) UnPadding(blockSize int, src []byte) ([]byte, error) {
	return src, nil
}

// Cipher 对称加密算法接口。
type Cipher interface {
	Block() cipher.Block
	BlockSize() int // 块大小（AES/SM4=16，DES/3DES=8）
	IVSize() int    // iv 长度
	// Deprecated: 无认证，仅限遗留协议兼容（详见 NewCTR 实现注释）。
	NewCTR(iv []byte) (StreamCipher, error)
	NewGCM(nonce []byte, opts ...Option) (CipherMode, error)
	NewGCMWithRandomNonce() (CipherMode, error)
	NewCBC(iv []byte, opts ...Option) (CipherMode, error)
	NewCBCWithRandomIV(opts ...Option) (CipherMode, error)
	// Deprecated: 不安全，仅限遗留数据兼容（详见 NewECB 实现注释）。
	NewECB(opts ...Option) (CipherMode, error)
	NewCFB(iv []byte, opts ...Option) (CipherMode, error)
	NewCFBWithRandomIV(opts ...Option) (CipherMode, error)
	NewOFB(iv []byte, opts ...Option) (CipherMode, error)
	NewOFBWithRandomIV(opts ...Option) (CipherMode, error)
}

// CipherMode 对称加密模式接口。
//
// 并发安全：Encrypt/Decrypt 方法级并发安全（各实现不共享可变状态，
// 同一实例可安全并发调用）；StreamCipher（CTR）持有流状态，其
// XORKeyStream/Stream 非并发安全，并发场景请各自构造独立实例。
type CipherMode interface {
	Encrypt(plainText []byte) (bytesconv.BytesResult, error)
	Decrypt(cipherText []byte) (bytesconv.BytesResult, error)
}

// StreamCipher 流式加密接口。
//
// 非并发安全：内部持有流状态（如 CTR 计数器），并发场景请各自构造独立实例。
type StreamCipher interface {
	XORKeyStream(src []byte) []byte
	Stream(reader io.Reader) io.Reader
}

// GenerateKey 返回算法的随机密钥、IV 与 nonce。
// 经注册表读取 CipherFactory 元数据（KeySize/IVSize；nonce 固定 12 字节），
// 三次独立分配与随机填充：避免 key/iv/nonce 共享同一底层数组，
// 防止调用方修改其中一个切片时意外影响另外两个。
func GenerateKey(algorithm string) (key, iv, nonce []byte, err error) {
	f, err := CipherFactoryFor(algorithm)
	if err != nil {
		return nil, nil, nil, err
	}

	key = make([]byte, f.KeySize)
	if err := common.FillRandom(key); err != nil {
		return nil, nil, nil, err
	}
	iv = make([]byte, f.IVSize)
	if err := common.FillRandom(iv); err != nil {
		return nil, nil, nil, err
	}
	nonce = make([]byte, nonceSize)
	if err := common.FillRandom(nonce); err != nil {
		return nil, nil, nil, err
	}

	return key, iv, nonce, nil
}

// BlockSize 返回算法的密钥长度和 IV 长度。未知算法返回 error。
// 注意：函数名中的 "BlockSize" 沿袭历史命名，实际返回 (keySize, ivSize)。
func BlockSize(algorithm string) (blockSize, ivSize int, err error) {
	f, err := CipherFactoryFor(algorithm)
	if err != nil {
		return 0, 0, err
	}

	return f.KeySize, f.IVSize, nil
}

// NewCipher 创建对称加密算法实例（经注册表分发）。
//
// 未注册对应引擎时（多半是调用方未 blank import crypto/symmetric 子包）
// 返回 "unsupported algorithm" 错误并提示导入路径。
//
// 遗留算法警告：
//   - DES/3DES：仅兼容遗留数据，禁止新用（块大小 8 字节，无法使用 GCM）。
//   - ECB/CTR：不安全，详见各自构造函数（NewECB / NewCTR）的 Deprecated 标注。
func NewCipher(algorithm string, key []byte) (Cipher, error) {
	f, err := CipherFactoryFor(algorithm)
	if err != nil {
		return nil, fmt.Errorf("no engine registered for %s; add blank import: _ \"github.com/charlienet/go-crypto/crypto/symmetric\" or _ \"github.com/charlienet/go-crypto/crypto/engines\" for all: %w", algorithm, ErrEngineNotRegistered)
	}

	return f.New(key)
}
