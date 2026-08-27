package keymgr

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"hash"
	"os"
	"path/filepath"
	"testing"

	"github.com/emmansun/gmsm/sm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rootcrypto "github.com/charlienet/go-crypto/crypto"
	_ "github.com/charlienet/go-crypto/crypto/asym" // 注册非对称引擎（NewAsymmetric 协议入口依赖）
)

// --- GenerateKeyPair 测试 ---

func TestGenerateKeyPair_RSA(t *testing.T) {
	kp, err := GenerateKeyPair(rootcrypto.RSA)
	require.NoError(t, err)
	assert.NotNil(t, kp.PrivateKey)
	assert.NotNil(t, kp.PublicKey)
	assert.IsType(t, &rsa.PrivateKey{}, kp.PrivateKey)
	assert.IsType(t, &rsa.PublicKey{}, kp.PublicKey)
}

func TestGenerateKeyPair_RSA_WithKeySize(t *testing.T) {
	kp, err := GenerateKeyPair(rootcrypto.RSA, rootcrypto.WithKeySize(4096))
	require.NoError(t, err)
	rsaKey := kp.PrivateKey.(*rsa.PrivateKey)
	assert.Equal(t, 4096, rsaKey.N.BitLen())
}

func TestGenerateKeyPair_SM2(t *testing.T) {
	kp, err := GenerateKeyPair(rootcrypto.SM2)
	require.NoError(t, err)
	assert.IsType(t, &sm2.PrivateKey{}, kp.PrivateKey)
}

func TestGenerateKeyPair_ECDSA(t *testing.T) {
	kp, err := GenerateKeyPair(rootcrypto.ECDSA)
	require.NoError(t, err)
	assert.IsType(t, &ecdsa.PrivateKey{}, kp.PrivateKey)
}

func TestGenerateKeyPair_ECDSA_WithCurve(t *testing.T) {
	kp, err := GenerateKeyPair(rootcrypto.ECDSA, rootcrypto.WithCurve("P384"))
	require.NoError(t, err)
	ecKey := kp.PrivateKey.(*ecdsa.PrivateKey)
	assert.Equal(t, "P-384", ecKey.Curve.Params().Name)
}

func TestGenerateKeyPair_Ed25519(t *testing.T) {
	kp, err := GenerateKeyPair(rootcrypto.ED25519)
	require.NoError(t, err)
	assert.IsType(t, ed25519.PrivateKey{}, kp.PrivateKey)
	assert.IsType(t, ed25519.PublicKey{}, kp.PublicKey)
}

func TestGenerateKeyPair_Unsupported(t *testing.T) {
	// 非法值：子包直接工厂返回 unsupported algorithm 错误
	_, err := GenerateKeyPair(rootcrypto.AsymmetricAlgorithm("INVALID"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported algorithm")

	// 子集外枚举：ECDH/X25519 是密钥协商算法，密钥生成入口直接拒绝
	//（错误不含 engine 缺失提示，子包直接工厂无注册表环节）
	_, err = GenerateKeyPair(rootcrypto.ECDH)
	assert.Error(t, err)
	assert.NotContains(t, err.Error(), "no engine registered")

	_, err = GenerateKeyPair(rootcrypto.X25519)
	assert.Error(t, err)
	assert.NotContains(t, err.Error(), "no engine registered")
}

// --- Marshal/Unmarshal 测试 ---

func TestKeyPair_MarshalPublicKey_AllFormats(t *testing.T) {
	algorithms := []rootcrypto.AsymmetricAlgorithm{rootcrypto.RSA, rootcrypto.SM2, rootcrypto.ECDSA, rootcrypto.ED25519}
	formats := []KeyFormat{KeyFormatBase64, KeyFormatPEM, KeyFormatHex, KeyFormatRaw}

	for _, algo := range algorithms {
		kp, err := GenerateKeyPair(algo)
		require.NoError(t, err)

		for _, format := range formats {
			data, err := MarshalPublicKey(kp.PublicKey, format)
			require.NoError(t, err, "algorithm=%s format=%d", algo, format)
			assert.NotEmpty(t, data, "algorithm=%s format=%d", algo, format)

			// 反向解析
			kp2, err := ParsePublicKeyPair(data, format)
			require.NoError(t, err, "algorithm=%s format=%d", algo, format)
			assert.NotNil(t, kp2.PublicKey)
		}
	}
}

func TestKeyPair_MarshalPrivateKey_AllFormats(t *testing.T) {
	algorithms := []rootcrypto.AsymmetricAlgorithm{rootcrypto.RSA, rootcrypto.SM2, rootcrypto.ECDSA, rootcrypto.ED25519}
	formats := []KeyFormat{KeyFormatBase64, KeyFormatPEM, KeyFormatHex, KeyFormatRaw}

	for _, algo := range algorithms {
		kp, err := GenerateKeyPair(algo)
		require.NoError(t, err)

		for _, format := range formats {
			data, err := MarshalPrivateKey(kp.PrivateKey, format)
			require.NoError(t, err, "algorithm=%s format=%d", algo, format)
			assert.NotEmpty(t, data, "algorithm=%s format=%d", algo, format)

			// 反向解析（自动提取公钥）
			kp2, err := ParsePrivateKeyPair(data, format)
			require.NoError(t, err, "algorithm=%s format=%d", algo, format)
			assert.NotNil(t, kp2.PrivateKey)
			assert.NotNil(t, kp2.PublicKey, "公钥应自动提取")
		}
	}
}

func TestKeyPair_MarshalPrivateKey_PKCS1(t *testing.T) {
	kp, err := GenerateKeyPair(rootcrypto.RSA)
	require.NoError(t, err)

	// PKCS#1 格式
	data, err := MarshalPrivateKey(kp.PrivateKey, KeyFormatPEM, WithRSAKeyFormat(RSAKeyFormatPKCS1))
	require.NoError(t, err)
	assert.Contains(t, string(data), "RSA PRIVATE KEY")

	// PKCS#8 格式（默认）
	data8, err := MarshalPrivateKey(kp.PrivateKey, KeyFormatPEM)
	require.NoError(t, err)
	assert.Contains(t, string(data8), "PRIVATE KEY")
	assert.NotContains(t, string(data8), "RSA PRIVATE KEY")
}

func TestKeyPair_MarshalNilKey(t *testing.T) {
	_, err := MarshalPublicKey(nil, KeyFormatPEM)
	assert.Error(t, err)

	_, err = MarshalPrivateKey(nil, KeyFormatPEM)
	assert.Error(t, err)
}

// --- 文件读写测试 ---

func TestKeyPair_SaveLoadPublicKey(t *testing.T) {
	dir := t.TempDir()
	formats := []struct {
		name   string
		format KeyFormat
		ext    string
	}{
		{"PEM", KeyFormatPEM, ".pem"},
		{"Base64", KeyFormatBase64, ".b64"},
		{"Hex", KeyFormatHex, ".hex"},
		{"Raw", KeyFormatRaw, ".der"},
	}

	for _, algo := range []rootcrypto.AsymmetricAlgorithm{rootcrypto.RSA, rootcrypto.SM2, rootcrypto.ECDSA, rootcrypto.ED25519} {
		kp, err := GenerateKeyPair(algo)
		require.NoError(t, err)

		for _, f := range formats {
			filename := filepath.Join(dir, algo.String()+"_pub"+f.ext)

			err = SavePublicKey(filename, kp.PublicKey, f.format)
			require.NoError(t, err)

			// 验证文件权限
			info, err := os.Stat(filename)
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0644), info.Mode().Perm())

			// 加载并验证
			kp2, err := LoadPublicKeyPair(filename, f.format)
			require.NoError(t, err)
			assert.NotNil(t, kp2.PublicKey)
		}
	}
}

func TestKeyPair_SaveLoadPrivateKey(t *testing.T) {
	dir := t.TempDir()

	kp, err := GenerateKeyPair(rootcrypto.RSA)
	require.NoError(t, err)

	filename := filepath.Join(dir, "priv.pem")
	err = SavePrivateKey(filename, kp.PrivateKey, KeyFormatPEM)
	require.NoError(t, err)

	// 验证文件权限（私钥应该是 0600）
	info, err := os.Stat(filename)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())

	// 加载
	kp2, err := LoadPrivateKeyPair(filename, KeyFormatPEM)
	require.NoError(t, err)
	assert.NotNil(t, kp2.PrivateKey)
	assert.NotNil(t, kp2.PublicKey, "加载私钥后应自动提取公钥")
}

// --- 包级加载函数测试 ---

func TestLoadKeyPair_PrivateKey(t *testing.T) {
	dir := t.TempDir()

	kp, _ := GenerateKeyPair(rootcrypto.RSA)
	filename := filepath.Join(dir, "priv.pem")
	SavePrivateKey(filename, kp.PrivateKey, KeyFormatPEM)

	loaded, err := LoadKeyPair(filename, KeyFormatPEM)
	require.NoError(t, err)
	assert.NotNil(t, loaded.PrivateKey)
	assert.NotNil(t, loaded.PublicKey)
}

func TestLoadKeyPair_PublicKey(t *testing.T) {
	dir := t.TempDir()

	kp, _ := GenerateKeyPair(rootcrypto.RSA)
	filename := filepath.Join(dir, "pub.pem")
	SavePublicKey(filename, kp.PublicKey, KeyFormatPEM)

	loaded, err := LoadKeyPair(filename, KeyFormatPEM)
	require.NoError(t, err)
	assert.Nil(t, loaded.PrivateKey)
	assert.NotNil(t, loaded.PublicKey)
}

func TestParseKeyPair(t *testing.T) {
	kp, _ := GenerateKeyPair(rootcrypto.RSA)

	// 解析私钥
	data, _ := MarshalPrivateKey(kp.PrivateKey, KeyFormatPEM)
	parsed, err := ParseKeyPair(data, KeyFormatPEM)
	require.NoError(t, err)
	assert.NotNil(t, parsed.PrivateKey)

	// 解析公钥
	data, _ = MarshalPublicKey(kp.PublicKey, KeyFormatPEM)
	parsed, err = ParseKeyPair(data, KeyFormatPEM)
	require.NoError(t, err)
	assert.Nil(t, parsed.PrivateKey)
	assert.NotNil(t, parsed.PublicKey)
}

// --- 并发安全测试 ---

func TestKeyPair_Concurrent_MarshalPublicKey(t *testing.T) {
	kp, _ := GenerateKeyPair(rootcrypto.RSA)

	done := make(chan bool, 20)
	formats := []KeyFormat{KeyFormatBase64, KeyFormatPEM, KeyFormatHex, KeyFormatRaw}

	for i := 0; i < 20; i++ {
		go func(idx int) {
			format := formats[idx%len(formats)]
			data, err := MarshalPublicKey(kp.PublicKey, format)
			assert.NoError(t, err)
			assert.NotEmpty(t, data)
			done <- true
		}(i)
	}

	for i := 0; i < 20; i++ {
		<-done
	}
}

func TestKeyPair_Concurrent_MarshalPrivateKey(t *testing.T) {
	kp, _ := GenerateKeyPair(rootcrypto.RSA)

	done := make(chan bool, 20)
	formats := []KeyFormat{KeyFormatBase64, KeyFormatPEM, KeyFormatHex, KeyFormatRaw}

	for i := 0; i < 20; i++ {
		go func(idx int) {
			format := formats[idx%len(formats)]
			data, err := MarshalPrivateKey(kp.PrivateKey, format)
			assert.NoError(t, err)
			assert.NotEmpty(t, data)
			done <- true
		}(i)
	}

	for i := 0; i < 20; i++ {
		<-done
	}
}

func TestGenerateKey_Concurrent(t *testing.T) {
	done := make(chan bool, 20)
	algorithms := []rootcrypto.AsymmetricAlgorithm{rootcrypto.RSA, rootcrypto.SM2, rootcrypto.ECDSA, rootcrypto.ED25519}

	for i := 0; i < 20; i++ {
		go func(idx int) {
			algo := algorithms[idx%len(algorithms)]
			kp, err := GenerateKeyPair(algo)
			assert.NoError(t, err)
			assert.NotNil(t, kp)
			assert.NotNil(t, kp.PrivateKey)
			assert.NotNil(t, kp.PublicKey)
			done <- true
		}(i)
	}

	for i := 0; i < 20; i++ {
		<-done
	}
}

func TestAsymmetric_Concurrent_SignVerify(t *testing.T) {
	algorithms := []rootcrypto.AsymmetricAlgorithm{rootcrypto.RSA, rootcrypto.SM2, rootcrypto.ECDSA, rootcrypto.ED25519}

	for _, algo := range algorithms {
		kp, err := GenerateKeyPair(algo)
		require.NoError(t, err)

		signer, err := rootcrypto.NewAsymmetric(algo, rootcrypto.WithPrivateKeyObject(kp.PrivateKey))
		require.NoError(t, err)

		verifier, err := rootcrypto.NewAsymmetric(algo, rootcrypto.WithPublicKeyObject(kp.PublicKey))
		require.NoError(t, err)

		done := make(chan bool, 10)
		data := []byte("concurrent sign verify test")

		for i := 0; i < 10; i++ {
			go func() {
				sig, err := signer.Sign(data)
				assert.NoError(t, err)
				assert.True(t, verifier.Verify(data, sig))
				done <- true
			}()
		}

		for i := 0; i < 10; i++ {
			<-done
		}
	}
}

// --- Race 检测 ---

func TestKeyPair_Race_MarshalUnmarshal(t *testing.T) {
	kp, _ := GenerateKeyPair(rootcrypto.RSA)

	// 预生成多算法私钥 PEM 数据，供并发 Unmarshal 使用（各 goroutine 操作独立实例）
	var datasets [][]byte
	for _, algo := range []rootcrypto.AsymmetricAlgorithm{rootcrypto.RSA, rootcrypto.SM2, rootcrypto.ECDSA, rootcrypto.ED25519} {
		gk, err := GenerateKeyPair(algo)
		require.NoError(t, err)
		data, err := MarshalPrivateKey(gk.PrivateKey, KeyFormatPEM)
		require.NoError(t, err)
		datasets = append(datasets, data)
	}

	done := make(chan bool, 20)

	// 并发 Marshal：共享只读实例（读路径应安全）
	for i := 0; i < 10; i++ {
		go func() {
			_, _ = MarshalPublicKey(kp.PublicKey, KeyFormatPEM)
			_, _ = MarshalPrivateKey(kp.PrivateKey, KeyFormatPEM)
			done <- true
		}()
	}

	// 并发 Unmarshal：各 goroutine 操作独立 KeyPair 实例（写路径互不干扰）
	for i := 0; i < 10; i++ {
		go func(idx int) {
			_, _ = ParsePrivateKeyPair(datasets[idx%len(datasets)], KeyFormatPEM)
			done <- true
		}(i)
	}

	for i := 0; i < 20; i++ {
		<-done
	}
}

// --- 生成侧弱密钥/弱曲线拒绝测试（P1 B1/B2） ---

func TestGenerateKeyPair_RSA_WeakKeySize(t *testing.T) {
	// 512/1024 位 RSA 已可被破解，生成侧必须拒绝
	_, err := GenerateKeyPair(rootcrypto.RSA, rootcrypto.WithKeySize(1024))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least 2048")

	// 默认 2048 位及以上的合法位数不受影响
	kp, err := GenerateKeyPair(rootcrypto.RSA)
	require.NoError(t, err)
	assert.NotNil(t, kp.PrivateKey)
}

func TestGenerateKeyPair_ECDSA_P224Rejected(t *testing.T) {
	// P224 曲线安全强度不足，必须拒绝
	_, err := GenerateKeyPair(rootcrypto.ECDSA, rootcrypto.WithCurve("P224"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "P224 is not supported")

	// P256/P384/P521 仍可用
	kp, err := GenerateKeyPair(rootcrypto.ECDSA, rootcrypto.WithCurve("P384"))
	require.NoError(t, err)
	assert.NotNil(t, kp.PrivateKey)
}

// --- 加载路径弱 RSA 拒绝测试（P1 B3） ---

func TestKeyPair_LoadWeakRSA_Rejected(t *testing.T) {
	weakKey, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	der := x509.MarshalPKCS1PrivateKey(weakKey)

	// Raw 格式直接喂 DER，经 parsePrivateKeyDER 的强度校验
	_, err = ParsePrivateKeyPair(der, KeyFormatRaw)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too weak")

	// 原方法路径（UnmarshalPrivateKey）已并入包级函数，语义等价
	_, err = ParsePrivateKeyPair(der, KeyFormatRaw)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too weak")

	// 合法 2048 位密钥不受影响
	strongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	derStrong := x509.MarshalPKCS1PrivateKey(strongKey)
	kp2, err := ParsePrivateKeyPair(derStrong, KeyFormatRaw)
	require.NoError(t, err)
	assert.NotNil(t, kp2.PrivateKey)
}

// --- PEM 私钥加密（PBES2）测试（P2） ---

func TestKeyPair_SaveLoadPrivateKey_Encrypted(t *testing.T) {
	algorithms := []rootcrypto.AsymmetricAlgorithm{rootcrypto.RSA, rootcrypto.ECDSA, rootcrypto.ED25519, rootcrypto.SM2}
	password := []byte("correct horse battery staple")

	for _, algo := range algorithms {
		kp, err := GenerateKeyPair(algo)
		require.NoError(t, err)

		dir := t.TempDir()
		filename := filepath.Join(dir, algo.String()+"_enc.pem")

		// 带密码保存：PEM 块类型应为 "ENCRYPTED PRIVATE KEY"（PBES2）
		err = SavePrivateKey(filename, kp.PrivateKey, KeyFormatPEM, WithEncryptionPassword(password))
		require.NoError(t, err, "algorithm=%s", algo)

		raw, err := os.ReadFile(filename)
		require.NoError(t, err)
		assert.Contains(t, string(raw), "ENCRYPTED PRIVATE KEY", "algorithm=%s", algo)

		// 正确密码可加载（往返成功）
		loaded, err := LoadPrivateKeyPair(filename, KeyFormatPEM, WithPassword(password))
		require.NoError(t, err, "algorithm=%s", algo)
		assert.NotNil(t, loaded.PrivateKey, "algorithm=%s", algo)
		assert.NotNil(t, loaded.PublicKey, "algorithm=%s", algo)

		// 数值一致性校验
		switch algo {
		case rootcrypto.RSA:
			orig := kp.PrivateKey.(*rsa.PrivateKey)
			loadedKey, ok := loaded.PrivateKey.(*rsa.PrivateKey)
			require.True(t, ok)
			assert.Equal(t, orig.N, loadedKey.N, "algorithm=%s", algo)
		case rootcrypto.ECDSA:
			orig := kp.PrivateKey.(*ecdsa.PrivateKey)
			loadedKey, ok := loaded.PrivateKey.(*ecdsa.PrivateKey)
			require.True(t, ok)
			assert.Equal(t, orig.D, loadedKey.D, "algorithm=%s", algo)
		case rootcrypto.ED25519:
			orig := kp.PrivateKey.(ed25519.PrivateKey)
			loadedKey, ok := loaded.PrivateKey.(ed25519.PrivateKey)
			require.True(t, ok)
			assert.Equal(t, orig, loadedKey, "algorithm=%s", algo)
		case rootcrypto.SM2:
			orig := kp.PrivateKey.(*sm2.PrivateKey)
			loadedKey, ok := loaded.PrivateKey.(*sm2.PrivateKey)
			require.True(t, ok)
			assert.Equal(t, orig.D, loadedKey.D, "algorithm=%s", algo)
		}

		// 错误密码必须拒绝
		_, err = LoadPrivateKeyPair(filename, KeyFormatPEM, WithPassword([]byte("wrong-password")))
		assert.Error(t, err, "algorithm=%s", algo)

		// 缺少密码必须拒绝
		_, err = LoadPrivateKeyPair(filename, KeyFormatPEM)
		assert.Error(t, err, "algorithm=%s", algo)
	}
}

func TestKeyPair_LoadPrivateKey_LegacyEncryptedPEM(t *testing.T) {
	// 构造旧传统 OpenSSL 加密格式样本。
	// x509.EncryptPEMBlock 官方已 Deprecated（弱 KDF），此处仅用于
	// 构造存量数据以验证读取兼容路径。
	kp, err := GenerateKeyPair(rootcrypto.RSA)
	require.NoError(t, err)
	rsaKey := kp.PrivateKey.(*rsa.PrivateKey)
	der := x509.MarshalPKCS1PrivateKey(rsaKey)

	block, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", der, []byte("legacy-pass"), x509.PEMCipherAES256)
	require.NoError(t, err)
	legacyPEM := pem.EncodeToMemory(block)

	// 正确密码可加载（旧格式读取兼容，保护存量数据）
	loaded, err := ParsePrivateKeyPair(legacyPEM, KeyFormatPEM, WithPassword([]byte("legacy-pass")))
	require.NoError(t, err)
	assert.NotNil(t, loaded.PrivateKey)
	assert.NotNil(t, loaded.PublicKey)

	// 错误密码仍拒绝
	_, err = ParsePrivateKeyPair(legacyPEM, KeyFormatPEM, WithPassword([]byte("wrong")))
	assert.Error(t, err)
}

func TestKeyPair_UnmarshalPrivateKey_PasswordOnlyPEM(t *testing.T) {
	kp, err := GenerateKeyPair(rootcrypto.ECDSA)
	require.NoError(t, err)

	b64, err := MarshalPrivateKey(kp.PrivateKey, KeyFormatBase64)
	require.NoError(t, err)

	// 非 PEM 格式传入密码：必须显式报错而非静默忽略
	_, err = ParsePrivateKeyPair(b64, KeyFormatBase64, WithPassword([]byte("secret")))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "password is only supported for PEM format")

	// 无密码路径不受影响（回归）
	parsed, err := ParsePrivateKeyPair(b64, KeyFormatBase64)
	require.NoError(t, err)
	assert.NotNil(t, parsed.PrivateKey)

	// 加密写入侧同样拒绝非 PEM 格式 + 密码
	_, err = MarshalPrivateKey(kp.PrivateKey, KeyFormatBase64, WithEncryptionPassword([]byte("secret")))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "password is only supported for PEM format")
}

// --- PBES2 解密路径加固测试（独立复核修复） ---

// buildPBES2SampleDER 手工构造 PBES2 EncryptedPrivateKeyInfo DER 样本。
// prfOID 为 nil 时省略 PBKDF2-params 的 PRF 字段（RFC 8018 默认 HMAC-SHA1）。
// 注意：样本构造仅用于生成密文，恶意参数的样本用截断值派生即可
// （迭代/长度上限检查发生在解密派生之前，密文内容无关紧要）。
func buildPBES2SampleDER(t *testing.T, hashNew func() hash.Hash, prfOID asn1.ObjectIdentifier, password string, plainDER, salt, iv []byte, iter, keyLen int) []byte {
	t.Helper()

	derivedIter := iter
	if derivedIter > 1000 {
		derivedIter = 1000
	}
	derivedKeyLen := keyLen
	if derivedKeyLen <= 0 || derivedKeyLen > 64 {
		derivedKeyLen = 32
	}
	dk, err := pbkdf2.Key(hashNew, password, salt, derivedIter, derivedKeyLen)
	require.NoError(t, err)
	defer func() {
		for i := range dk {
			dk[i] = 0
		}
	}()

	block, err := aes.NewCipher(dk)
	require.NoError(t, err)
	padded := pkcs7Pad(plainDER, aes.BlockSize)
	defer func() {
		for i := range padded {
			padded[i] = 0
		}
	}()
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	prf := asn1AlgorithmIdentifier{Algorithm: prfOID, Parameters: asn1.NullRawValue}
	pbkdf2ParamsDER, err := asn1.Marshal(asn1PBKDF2Params{
		Salt:           salt,
		IterationCount: iter,
		KeyLength:      keyLen,
		PRF:            prf,
	})
	require.NoError(t, err)
	ivDER, err := asn1.Marshal(iv)
	require.NoError(t, err)
	pbes2ParamsDER, err := asn1.Marshal(asn1PBES2Params{
		KeyDerivationFunc: asn1AlgorithmIdentifier{Algorithm: oidPBKDF2, Parameters: asn1.RawValue{FullBytes: pbkdf2ParamsDER}},
		EncryptionScheme:  asn1AlgorithmIdentifier{Algorithm: oidAES256CBC, Parameters: asn1.RawValue{FullBytes: ivDER}},
	})
	require.NoError(t, err)
	der, err := asn1.Marshal(asn1EncryptedPrivateKeyInfo{
		EncryptionAlgorithm: asn1AlgorithmIdentifier{Algorithm: oidPBES2, Parameters: asn1.RawValue{FullBytes: pbes2ParamsDER}},
		EncryptedData:       ciphertext,
	})
	require.NoError(t, err)
	return der
}

// TestDecryptPBES2_IterationCountLimit：恶意 IterationCount/KeyLength 必须在
// 派生前被拒绝（防 DoS），错误信息不含具体数值。
func TestDecryptPBES2_IterationCountLimit(t *testing.T) {
	salt := []byte("0123456789abcdef")
	iv := make([]byte, 16)
	for i := range iv {
		iv[i] = byte(i)
	}

	// IterationCount=2^31-1：快速返回 error，不做派生
	der := buildPBES2SampleDER(t, sha1.New, oidHMACWithSHA1, "pw", []byte("dummy"), salt, iv, (1<<31)-1, 32)
	_, err := decryptPBES2PrivateKey(der, []byte("pw"))
	assert.Error(t, err)

	// KeyLength=1<<30：超上限拒绝
	der = buildPBES2SampleDER(t, sha1.New, oidHMACWithSHA1, "pw", []byte("dummy"), salt, iv, 1000, 1<<30)
	_, err = decryptPBES2PrivateKey(der, []byte("pw"))
	assert.Error(t, err)

	// 合法参数不应误伤：用错误密码使解密/填充阶段报错，
	// 但错误绝非"迭代次数"（证明上限检查未误伤合法输入）
	der = buildPBES2SampleDER(t, sha1.New, oidHMACWithSHA1, "pw", []byte("dummy"), salt, iv, 1000, 32)
	_, err = decryptPBES2PrivateKey(der, []byte("wrong-password"))
	assert.Error(t, err)
	assert.NotContains(t, err.Error(), "iteration count")
}

// TestDecryptPBES2_SHA1PRF：SHA1-PRF（RFC 8018 默认）读取分支真实样本验证；
// 未知 PRF OID 安全失败。
func TestDecryptPBES2_SHA1PRF(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	plainDER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	require.NoError(t, err)

	salt := []byte("0123456789abcdef")
	iv := make([]byte, 16)
	for i := range iv {
		iv[i] = byte(i)
	}

	// 显式 SHA1-PRF 样本：解密侧须成功解密且还原原始 DER
	der := buildPBES2SampleDER(t, sha1.New, oidHMACWithSHA1, "pw", plainDER, salt, iv, 1000, 32)
	out, err := decryptPBES2PrivateKey(der, []byte("pw"))
	require.NoError(t, err)
	defer func() {
		for i := range out {
			out[i] = 0
		}
	}()
	assert.Equal(t, plainDER, out)

	// 未知 PRF OID：必须安全失败（不 panic、快速返回）
	derUnknown := buildPBES2SampleDER(t, sha256.New, asn1.ObjectIdentifier{1, 2, 3, 4}, "pw", plainDER, salt, iv, 1000, 32)
	_, err = decryptPBES2PrivateKey(derUnknown, []byte("pw"))
	assert.Error(t, err)
}
