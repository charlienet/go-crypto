package keymgr

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
)

// --- PBES2（PKCS#5 v2.1）私钥加密，RFC 8018 / RFC 5958 ---
//
// 取代已弃用的 x509.EncryptPEMBlock（传统 OpenSSL 格式，弱 KDF）。
// 使用 PBKDF2-HMAC-SHA256 派生密钥 + AES-256-CBC 加密 PKCS#8 DER。

// PBES2 相关 OID
var (
	oidPBES2          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidAES256CBC      = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidHMACWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidHMACWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
)

// pbes2PBKDF2Iterations PBKDF2 迭代次数。
// 参考 OWASP 密码存储建议（2023+）：PBKDF2-HMAC-SHA256 不低于 600,000 次。
const pbes2PBKDF2Iterations = 600_000

// pbes2MaxIterations 解密侧接受的 PBKDF2 最大迭代次数。
// 用于防御恶意 PEM（如 IterationCount=2^31-1）对解密路径的 DoS 攻击。
const pbes2MaxIterations = 10_000_000

// pbes2MaxKeyLen 解密侧接受的 PBKDF2 派生密钥最大长度（字节）。
// AES-256-CBC 需要 32 字节，预留安全余量；超限拒绝，防恶意 keyLen 放大内存。
const pbes2MaxKeyLen = 64

type asn1AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// asn1EncryptedPrivateKeyInfo 对应 RFC 5958 EncryptedPrivateKeyInfo
type asn1EncryptedPrivateKeyInfo struct {
	EncryptionAlgorithm asn1AlgorithmIdentifier
	EncryptedData       []byte
}

// asn1PBES2Params 对应 RFC 8018 PBES2-params
type asn1PBES2Params struct {
	KeyDerivationFunc asn1AlgorithmIdentifier
	EncryptionScheme  asn1AlgorithmIdentifier
}

// asn1PBKDF2Params 对应 RFC 8018 PBKDF2-params（salt 仅支持 OCTET STRING 形式）
type asn1PBKDF2Params struct {
	Salt           []byte
	IterationCount int
	KeyLength      int                     `asn1:"optional"`
	PRF            asn1AlgorithmIdentifier `asn1:"optional"`
}

// encryptPrivateKeyDER 使用 PBES2 加密 PKCS#8 私钥 DER，返回
// EncryptedPrivateKeyInfo 的 DER 编码，供 PEM 块 "ENCRYPTED PRIVATE KEY" 使用。
func encryptPrivateKeyDER(pkcs8DER, password []byte) ([]byte, error) {
	// 明文 PKCS#8 DER 在加密完成后原地清零（与解密侧对称），
	// 避免私钥明文残留在调用方缓冲中。
	defer func() {
		for i := range pkcs8DER {
			pkcs8DER[i] = 0
		}
	}()

	// 随机 16 字节 salt（PBKDF2 输入，非机密）
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	// PBKDF2-HMAC-SHA256 派生 32 字节密钥（AES-256）。
	// 注：crypto/pbkdf2 标准库 API 仅接受 string 密码，string 转换会留下
	// 不可清零的副本，这是标准库 API 限制，无法规避。
	dk, err := pbkdf2.Key(sha256.New, string(password), salt, pbes2PBKDF2Iterations, 32)
	if err != nil {
		return nil, err
	}
	defer func() {
		for i := range dk {
			dk[i] = 0
		}
	}()

	// 随机 16 字节 IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, err
	}
	// PKCS#7 填充后 AES-256-CBC 加密；填充缓冲含明文私钥，用完清零
	padded := pkcs7Pad(pkcs8DER, aes.BlockSize)
	defer func() {
		for i := range padded {
			padded[i] = 0
		}
	}()
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	// 组装 PBES2 EncryptedPrivateKeyInfo
	prf := asn1AlgorithmIdentifier{Algorithm: oidHMACWithSHA256, Parameters: asn1.NullRawValue}
	pbkdf2ParamsDER, err := asn1.Marshal(asn1PBKDF2Params{
		Salt:           salt,
		IterationCount: pbes2PBKDF2Iterations,
		KeyLength:      32,
		PRF:            prf,
	})
	if err != nil {
		return nil, err
	}
	ivDER, err := asn1.Marshal(iv)
	if err != nil {
		return nil, err
	}
	pbes2ParamsDER, err := asn1.Marshal(asn1PBES2Params{
		KeyDerivationFunc: asn1AlgorithmIdentifier{Algorithm: oidPBKDF2, Parameters: asn1.RawValue{FullBytes: pbkdf2ParamsDER}},
		EncryptionScheme:  asn1AlgorithmIdentifier{Algorithm: oidAES256CBC, Parameters: asn1.RawValue{FullBytes: ivDER}},
	})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(asn1EncryptedPrivateKeyInfo{
		EncryptionAlgorithm: asn1AlgorithmIdentifier{Algorithm: oidPBES2, Parameters: asn1.RawValue{FullBytes: pbes2ParamsDER}},
		EncryptedData:       ciphertext,
	})
}

// decryptPBES2PrivateKey 解密 PBES2 加密的 EncryptedPrivateKeyInfo，
// 返回解密的 PKCS#8 私钥 DER（调用方负责及时清零）。
func decryptPBES2PrivateKey(der, password []byte) ([]byte, error) {
	var epki asn1EncryptedPrivateKeyInfo
	rest, err := asn1.Unmarshal(der, &epki)
	if err != nil {
		return nil, fmt.Errorf("invalid EncryptedPrivateKeyInfo: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("invalid EncryptedPrivateKeyInfo: trailing data")
	}
	if !epki.EncryptionAlgorithm.Algorithm.Equal(oidPBES2) {
		return nil, errors.New("unsupported private key encryption algorithm (not PBES2)")
	}

	var p2 asn1PBES2Params
	if _, err := asn1.Unmarshal(epki.EncryptionAlgorithm.Parameters.FullBytes, &p2); err != nil {
		return nil, fmt.Errorf("invalid PBES2 params: %w", err)
	}
	if !p2.KeyDerivationFunc.Algorithm.Equal(oidPBKDF2) {
		return nil, errors.New("unsupported key derivation function (not PBKDF2)")
	}
	if !p2.EncryptionScheme.Algorithm.Equal(oidAES256CBC) {
		return nil, errors.New("unsupported encryption scheme (not AES-256-CBC)")
	}

	var p2k asn1PBKDF2Params
	if _, err := asn1.Unmarshal(p2.KeyDerivationFunc.Parameters.FullBytes, &p2k); err != nil {
		return nil, fmt.Errorf("invalid PBKDF2 params: %w", err)
	}
	// 迭代次数上限：拒绝恶意 PEM（如 2^31-1 次迭代）的 DoS 攻击。
	// 错误信息不含具体数值，避免向攻击者泄露内部上限。
	if p2k.IterationCount <= 0 || p2k.IterationCount > pbes2MaxIterations {
		return nil, errors.New("invalid PBKDF2 iteration count")
	}

	var iv []byte
	if _, err := asn1.Unmarshal(p2.EncryptionScheme.Parameters.FullBytes, &iv); err != nil {
		return nil, fmt.Errorf("invalid AES IV: %w", err)
	}
	if len(iv) != aes.BlockSize {
		return nil, errors.New("invalid AES IV length")
	}

	// 确定 PRF：RFC 8018 默认 HMAC-SHA1；写入侧固定 HMAC-SHA256
	hashNew := sha256.New
	if len(p2k.PRF.Algorithm) > 0 {
		switch {
		case p2k.PRF.Algorithm.Equal(oidHMACWithSHA256):
			hashNew = sha256.New
		case p2k.PRF.Algorithm.Equal(oidHMACWithSHA1):
			hashNew = sha1.New
		default:
			return nil, errors.New("unsupported PBKDF2 PRF")
		}
	}

	keyLen := p2k.KeyLength
	if keyLen <= 0 {
		// AES-256-CBC 需要 32 字节密钥
		keyLen = 32
	} else if keyLen > pbes2MaxKeyLen {
		// 派生密钥长度上限：防恶意 KeyLength 放大派生内存
		return nil, errors.New("invalid PBKDF2 key length")
	}
	// 注：crypto/pbkdf2 标准库 API 仅接受 string 密码，string 转换会留下
	// 不可清零的副本，这是标准库 API 限制，无法规避。
	dk, err := pbkdf2.Key(hashNew, string(password), p2k.Salt, p2k.IterationCount, keyLen)
	if err != nil {
		return nil, err
	}
	defer func() {
		for i := range dk {
			dk[i] = 0
		}
	}()

	if len(epki.EncryptedData) == 0 || len(epki.EncryptedData)%aes.BlockSize != 0 {
		return nil, errors.New("invalid encrypted data length")
	}
	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, len(epki.EncryptedData))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, epki.EncryptedData)
	return pkcs7Unpad(plaintext, aes.BlockSize)
}

// pkcs7Pad 按 PKCS#7 填充至 blockSize 的整数倍
func pkcs7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - len(data)%blockSize
	padded := make([]byte, len(data)+padLen)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}
	return padded
}

// pkcs7Unpad 校验并移除 PKCS#7 填充，填充非法时返回错误
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errors.New("invalid padded data length")
	}
	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > blockSize || padLen > len(data) {
		return nil, errors.New("invalid PKCS#7 padding")
	}
	for _, b := range data[len(data)-padLen:] {
		if int(b) != padLen {
			return nil, errors.New("invalid PKCS#7 padding")
		}
	}
	return data[:len(data)-padLen], nil
}
