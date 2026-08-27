package keymgr

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

func marshalPublicKey(key crypto.PublicKey, format KeyFormat) ([]byte, error) {
	var der []byte
	var err error
	var pemType string

	switch k := key.(type) {
	case *rsa.PublicKey:
		der, err = x509.MarshalPKIXPublicKey(k)
		pemType = "PUBLIC KEY"
	case *ecdsa.PublicKey:
		// 检查是否为SM2公钥
		if sm2.IsSM2PublicKey(k) {
			// 使用gmsm库的SM2密钥编码
			// sm2.PublicKey embeds ecdsa.PublicKey, so we need to cast differently
			der, err = smx509.MarshalPKIXPublicKey(k)
			pemType = "PUBLIC KEY"
		} else {
			der, err = x509.MarshalPKIXPublicKey(k)
			pemType = "PUBLIC KEY"
		}
	case ed25519.PublicKey:
		der, err = x509.MarshalPKIXPublicKey(k)
		pemType = "PUBLIC KEY"
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", key)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	return encode(der, format, pemType)
}

func marshalPrivateKey(key crypto.PrivateKey, format KeyFormat, cfg *marshalConfig) ([]byte, error) {
	var der []byte
	var err error
	var pemType string

	// 加密仅支持 PEM 输出格式；其他格式与密码同时使用属误用，显式报错而非静默忽略
	encrypted := cfg != nil && len(cfg.password) > 0
	if encrypted && format != KeyFormatPEM {
		return nil, errors.New("password is only supported for PEM format")
	}

	switch k := key.(type) {
	case *rsa.PrivateKey:
		if !encrypted && cfg != nil && cfg.rsaFormat == RSAKeyFormatPKCS1 {
			der = x509.MarshalPKCS1PrivateKey(k)
			pemType = "RSA PRIVATE KEY"
		} else {
			// 加密路径统一导出为 PKCS#8
			der, err = x509.MarshalPKCS8PrivateKey(k)
			pemType = "PRIVATE KEY"
		}
	case *ecdsa.PrivateKey:
		// 检查是否为SM2私钥
		if sm2.IsSM2PublicKey(&k.PublicKey) {
			// 使用gmsm库的SM2私钥编码
			// Create a new sm2.PrivateKey with the same values
			sm2Key := &sm2.PrivateKey{
				PrivateKey: *k,
			}
			der, err = smx509.MarshalPKCS8PrivateKey(sm2Key)
			pemType = "PRIVATE KEY"
		} else {
			der, err = x509.MarshalPKCS8PrivateKey(k)
			pemType = "PRIVATE KEY"
		}
	case *sm2.PrivateKey:
		// 直接处理sm2.PrivateKey
		der, err = smx509.MarshalPKCS8PrivateKey(k)
		pemType = "PRIVATE KEY"
	case ed25519.PrivateKey:
		der, err = x509.MarshalPKCS8PrivateKey(k)
		pemType = "PRIVATE KEY"
	default:
		return nil, fmt.Errorf("unsupported private key type: %T", key)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	if encrypted {
		// 使用 PBES2（PBKDF2-HMAC-SHA256 + AES-256-CBC）加密 PKCS#8 DER，
		// 输出块类型固定为 "ENCRYPTED PRIVATE KEY"（RFC 5958）
		der, err = encryptPrivateKeyDER(der, cfg.password)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt private key: %w", err)
		}
		pemType = "ENCRYPTED PRIVATE KEY"
	}

	return encode(der, format, pemType)
}

func unmarshalPublicKey(data []byte, format KeyFormat) (crypto.PublicKey, error) {
	der, err := decode(data, format)
	if err != nil {
		return nil, err
	}

	// 首先尝试使用标准库解析
	key, err := x509.ParsePKIXPublicKey(der)
	if err == nil {
		return key, nil
	}

	// 如果标准库解析失败，尝试使用gmsm库解析SM2
	key, err = smx509.ParsePKIXPublicKey(der)
	if err == nil {
		return key, nil
	}

	return nil, errors.New("unsupported public key format")
}

func unmarshalPrivateKey(data []byte, format KeyFormat, password []byte) (crypto.PrivateKey, error) {
	// 密码仅支持 PEM 加密格式；Base64/Hex/Raw 等格式传入密码属误用，
	// 显式报错而非静默忽略。
	if format != KeyFormatPEM && len(password) > 0 {
		return nil, errors.New("password is only supported for PEM format")
	}

	der, err := decode(data, format)
	if err != nil {
		return nil, err
	}

	defer func() {
		for i := range der {
			der[i] = 0
		}
	}()

	return parsePrivateKeyDER(der)
}

// unmarshalPrivateKeyWithPassword 解析私钥数据，优先处理 PEM 加密格式
// （PBES2 新格式与 x509 传统格式），返回解析出的私钥。
func unmarshalPrivateKeyWithPassword(data []byte, format KeyFormat, cfg *loadConfig) (crypto.PrivateKey, error) {
	if format == KeyFormatPEM {
		block, _ := pem.Decode(data)
		if block != nil {
			// 新格式：PBES2（PBKDF2-HMAC-SHA256 + AES-256-CBC）加密的 PKCS#8，
			// PEM 块类型为 "ENCRYPTED PRIVATE KEY"（RFC 5958）
			if block.Type == "ENCRYPTED PRIVATE KEY" {
				if cfg.password == nil {
					return nil, errors.New("private key is encrypted, password required")
				}
				der, err := decryptPBES2PrivateKey(block.Bytes, cfg.password)
				if err != nil {
					return nil, fmt.Errorf("failed to decrypt PEM: %w", err)
				}
				defer func() {
					for i := range der {
						der[i] = 0
					}
				}()
				return parsePrivateKeyDER(der)
			}

			// 旧传统格式（OpenSSL 传统加密，弱 KDF，官方已 Deprecated）：
			// 仅保留读取兼容以保护存量数据，新写入一律使用 PBES2。
			if x509.IsEncryptedPEMBlock(block) {
				if cfg.password == nil {
					return nil, errors.New("private key is encrypted, password required")
				}
				der, err := x509.DecryptPEMBlock(block, cfg.password)
				if err != nil {
					return nil, fmt.Errorf("failed to decrypt PEM: %w", err)
				}
				defer func() {
					for i := range der {
						der[i] = 0
					}
				}()
				return parsePrivateKeyDER(der)
			}
		}
	}

	return unmarshalPrivateKey(data, format, cfg.password)
}

func parsePrivateKeyDER(der []byte) (crypto.PrivateKey, error) {
	// 首先尝试使用标准库解析PKCS8
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err == nil {
		return validateParsedPrivateKeyStrength(key)
	}

	// 尝试使用gmsm库解析SM2 PKCS8
	sm2Key, err := smx509.ParsePKCS8PrivateKey(der)
	if err == nil {
		return sm2Key, nil
	}

	// 尝试解析PKCS1 RSA
	rsaKey, err := x509.ParsePKCS1PrivateKey(der)
	if err == nil {
		return validateParsedPrivateKeyStrength(rsaKey)
	}

	// 尝试解析EC私钥
	ecKey, err := x509.ParseECPrivateKey(der)
	if err == nil {
		return ecKey, nil
	}

	return nil, errors.New("unsupported private key format")
}

// validateParsedPrivateKeyStrength 校验解析出的私钥强度：RSA 私钥低于 2048 位直接拒绝，
// 错误消息与 rsa.go 字符串注入路径的弱密钥策略保持一致，避免语义冲突。
func validateParsedPrivateKeyStrength(key crypto.PrivateKey) (crypto.PrivateKey, error) {
	if rsaKey, ok := key.(*rsa.PrivateKey); ok {
		if rsaKey.N.BitLen() < 2048 {
			bits := rsaKey.N.BitLen()
			return nil, fmt.Errorf("RSA private key too weak: %d bits, minimum required is 2048 bits", bits)
		}
	}
	return key, nil
}

func encode(der []byte, format KeyFormat, pemType string) ([]byte, error) {
	switch format {
	case KeyFormatBase64:
		encoded := base64.StdEncoding.EncodeToString(der)
		return []byte(encoded), nil
	case KeyFormatPEM:
		block := &pem.Block{
			Type:  pemType,
			Bytes: der,
		}
		return pem.EncodeToMemory(block), nil
	case KeyFormatHex:
		encoded := hex.EncodeToString(der)
		return []byte(encoded), nil
	case KeyFormatRaw:
		result := make([]byte, len(der))
		copy(result, der)
		return result, nil
	default:
		return nil, fmt.Errorf("unsupported key format: %d", format)
	}
}

func decode(data []byte, format KeyFormat) ([]byte, error) {
	switch format {
	case KeyFormatBase64:
		return base64.StdEncoding.DecodeString(string(data))
	case KeyFormatPEM:
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, errors.New("failed to decode PEM block")
		}
		return block.Bytes, nil
	case KeyFormatHex:
		return hex.DecodeString(string(data))
	case KeyFormatRaw:
		result := make([]byte, len(data))
		copy(result, data)
		return result, nil
	default:
		return nil, fmt.Errorf("unsupported key format: %d", format)
	}
}

// --- 辅助函数 ---

// extractPublicKey 从私钥提取对应公钥。
func extractPublicKey(key crypto.PrivateKey) crypto.PublicKey {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case *sm2.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public()
	default:
		return nil
	}
}

// detectAlgorithm 检测密钥对象的算法名（NormalizeAlgorithm 规范形式）。
func detectAlgorithm(key interface{}) string {
	switch k := key.(type) {
	case *rsa.PrivateKey, *rsa.PublicKey:
		return "RSA"
	case *sm2.PrivateKey:
		return "SM2"
	case *ecdsa.PrivateKey:
		// Check if it's an SM2 key by checking if the corresponding public key is an SM2 key
		if sm2.IsSM2PublicKey(&k.PublicKey) {
			return "SM2"
		}
		return "ECDSA"
	case *ecdsa.PublicKey:
		if sm2.IsSM2PublicKey(k) {
			return "SM2"
		}
		return "ECDSA"
	case ed25519.PrivateKey:
		return "Ed25519"
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return ""
	}
}
