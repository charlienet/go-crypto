package keymgr

import (
	"crypto"
	"errors"
	"os"
)

// KeyFormat 密钥编码格式
type KeyFormat int

const (
	KeyFormatBase64 KeyFormat = iota // Base64 编码的 DER（默认）
	KeyFormatPEM                     // PEM 文本格式
	KeyFormatHex                     // 十六进制编码的 DER
	KeyFormatRaw                     // 原始 DER 字节
)

// RSAKeyFormat RSA 私钥结构格式
type RSAKeyFormat int

const (
	RSAKeyFormatPKCS8 RSAKeyFormat = iota // PKCS#8（默认）
	RSAKeyFormatPKCS1                     // PKCS#1
)

// MarshalOption 导出选项
type MarshalOption func(*marshalConfig)

type marshalConfig struct {
	rsaFormat RSAKeyFormat
	password  []byte
}

// WithRSAKeyFormat 设置 RSA 私钥导出格式
func WithRSAKeyFormat(format RSAKeyFormat) MarshalOption {
	return func(cfg *marshalConfig) {
		cfg.rsaFormat = format
	}
}

// WithEncryptionPassword 设置 PEM 私钥导出加密密码。
// 使用 PBES2（PBKDF2-HMAC-SHA256 + AES-256-CBC，RFC 8018）加密，
// 输出 PEM 块类型为 "ENCRYPTED PRIVATE KEY"；
// 仅对 KeyFormatPEM 生效，其他格式与密码同时使用会返回错误。
func WithEncryptionPassword(password []byte) MarshalOption {
	return func(cfg *marshalConfig) {
		cfg.password = password
	}
}

// LoadOption 加载选项
type LoadOption func(*loadConfig)

type loadConfig struct {
	password []byte
}

// WithPassword 设置密码（用于加密的 PEM）
func WithPassword(password []byte) LoadOption {
	return func(cfg *loadConfig) {
		cfg.password = password
	}
}

// MarshalPublicKey 将公钥编码为指定格式。
func MarshalPublicKey(pub crypto.PublicKey, format KeyFormat) ([]byte, error) {
	if pub == nil {
		return nil, errors.New("public key is nil")
	}
	return marshalPublicKey(pub, format)
}

// MarshalPrivateKey 将私钥编码为指定格式。
func MarshalPrivateKey(priv crypto.PrivateKey, format KeyFormat, opts ...MarshalOption) ([]byte, error) {
	if priv == nil {
		return nil, errors.New("private key is nil")
	}
	cfg := &marshalConfig{rsaFormat: RSAKeyFormatPKCS8}
	for _, opt := range opts {
		opt(cfg)
	}
	return marshalPrivateKey(priv, format, cfg)
}

// SavePublicKey 将公钥编码并写入文件（权限 0644）。
func SavePublicKey(filename string, pub crypto.PublicKey, format KeyFormat) error {
	data, err := MarshalPublicKey(pub, format)
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

// SavePrivateKey 将私钥编码并写入文件（权限 0600）。
func SavePrivateKey(filename string, priv crypto.PrivateKey, format KeyFormat, opts ...MarshalOption) error {
	data, err := MarshalPrivateKey(priv, format, opts...)
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0600)
}
