package asym_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"strings"
	"sync"
	"testing"

	rootcrypto "github.com/charlienet/go-crypto"
	_ "github.com/charlienet/go-crypto/keymgr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 包级共享的 2048 位测试密钥对：懒生成一次，供多个用例复用，
// 避免每个用例各生成一把 2048 位密钥拖慢测试。密钥随机生成，不打印明文。
var (
	testRSAPairOnce sync.Once
	testRSAPairPrv  *rsa.PrivateKey
	testRSAPairErr  error
)

// getTestRSAPair 返回懒生成的 2048 位测试私钥。
func getTestRSAPair(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	testRSAPairOnce.Do(func() {
		testRSAPairPrv, testRSAPairErr = rsa.GenerateKey(rand.Reader, 2048)
	})
	if testRSAPairErr != nil {
		t.Fatalf("生成测试 RSA 密钥失败: %v", testRSAPairErr)
	}
	return testRSAPairPrv
}

// newTestRSAAlgo 以共享 2048 位密钥构造 Asymmetric 实例。
func newTestRSAAlgo(t *testing.T) rootcrypto.Asymmetric {
	t.Helper()
	prv := getTestRSAPair(t)

	prkBytes, err := x509.MarshalPKCS8PrivateKey(prv)
	if err != nil {
		t.Fatal(err)
	}
	pubBytes, err := x509.MarshalPKIXPublicKey(&prv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	s, err := rootcrypto.NewAsymmetric(rootcrypto.RSA,
		rootcrypto.WithPrivateKey(base64.StdEncoding.EncodeToString(prkBytes)),
		rootcrypto.WithPublicKey(base64.StdEncoding.EncodeToString(pubBytes)),
	)
	if err != nil {
		t.Fatalf("构造 RSA 算法实例失败: %v", err)
	}
	return s
}

// TestRSASignVerify：密钥生成 → Sign → Verify 往返成功（标准 PSS）。
func TestRSASignVerify(t *testing.T) {
	s := newTestRSAAlgo(t)

	msg := []byte("hello, standard RSASSA-PSS")
	sig, err := s.Sign(msg)
	assert.NoError(t, err)
	assert.NotEmpty(t, sig)

	assert.True(t, s.Verify(msg, sig), "合法签名验证失败")
}

// TestRSAVerifyTampered：篡改签名或消息均应验证失败。
func TestRSAVerifyTampered(t *testing.T) {
	s := newTestRSAAlgo(t)

	msg := []byte("integrity check")
	sig, err := s.Sign(msg)
	assert.NoError(t, err)

	// 篡改签名中的一个字节
	tamperedSig := append([]byte(nil), sig...)
	tamperedSig[len(tamperedSig)/2] ^= 0x01
	assert.False(t, s.Verify(msg, tamperedSig), "篡改后的签名被接受")

	// 篡改消息
	assert.False(t, s.Verify(append(msg, 'x'), sig), "篡改后的消息被接受")
}

// TestRSAStandardPSSInterop：证明签名是标准 RSASSA-PSS，可跨实现互通。
// 用标准库 rsa.SignPSS（独立实现）对同一消息摘要签名，项目 Verify 应验证通过；
// 反向，项目签名也应被标准库 rsa.VerifyPSS 接受。
func TestRSAStandardPSSInterop(t *testing.T) {
	prv := getTestRSAPair(t)
	s := newTestRSAAlgo(t)

	msg := []byte("standard PSS interop across implementations")

	h := crypto.SHA256.New()
	h.Write(msg)
	digest := h.Sum(nil)

	// 独立实现签名：标准库直接对消息摘要做 PSS
	stdSig, err := rsa.SignPSS(rand.Reader, prv, crypto.SHA256, digest, nil)
	assert.NoError(t, err, "标准库 SignPSS 失败")

	// 项目 Verify 应能验证标准库生成的签名
	assert.True(t, s.Verify(msg, stdSig), "项目 Verify 拒绝标准库 rsa.SignPSS 生成的签名")

	// 反向验证：项目签名应被标准库 VerifyPSS 接受
	projSig, err := s.Sign(msg)
	assert.NoError(t, err, "项目 Sign 失败")

	err = rsa.VerifyPSS(&prv.PublicKey, crypto.SHA256, digest, projSig, nil)
	assert.NoError(t, err, "标准库 VerifyPSS 拒绝项目签名")

	// 显式盐长互操作：项目 Sign/Verify 内部使用 PSSSaltLengthEqualsHash，
	// 标准库以相同盐长策略签名/验证应完全互通。
	explicitOpts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}

	stdSigExplicit, err := rsa.SignPSS(rand.Reader, prv, crypto.SHA256, digest, explicitOpts)
	assert.NoError(t, err, "标准库 SignPSS（显式盐长）失败")
	assert.True(t, s.Verify(msg, stdSigExplicit), "项目 Verify 拒绝显式盐长的标准库签名")

	err = rsa.VerifyPSS(&prv.PublicKey, crypto.SHA256, digest, projSig, explicitOpts)
	assert.NoError(t, err, "标准库以显式盐长 VerifyPSS 拒绝项目签名")
}

// TestRSAWeakKeyRejected：1024 位弱密钥构造应被拒绝（A 库 fail-fast 语义）。
func TestRSAWeakKeyRejected(t *testing.T) {
	weakKey, err := rsa.GenerateKey(rand.Reader, 1024)
	assert.NoError(t, err, "生成 1024 位测试密钥失败")
	assert.Equal(t, 1024, weakKey.N.BitLen(), "预期 1024 位密钥")

	prkB64 := base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PrivateKey(weakKey))

	// A 库 fail-fast 语义：1024 位弱私钥在构造期应被拒绝
	_, err = rootcrypto.NewAsymmetric(rootcrypto.RSA, rootcrypto.WithPrivateKey(prkB64))
	assert.Error(t, err, "1024 位弱私钥应被拒绝，实际被接受")
	assert.True(t, strings.Contains(err.Error(), "too weak"),
		"弱密钥错误信息不符合预期: %v", err)
}

// TestRSAWeakKeyRejected_ObjectPath：对象注入路径同样拒绝 <2048 位弱密钥
// （与字符串路径策略对称，P1 修复）。
func TestRSAWeakKeyRejected_ObjectPath(t *testing.T) {
	weakKey, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	// 私钥对象注入路径：构造必须失败
	_, err = rootcrypto.NewAsymmetric(rootcrypto.RSA, rootcrypto.WithPrivateKeyObject(weakKey))
	assert.Error(t, err, "1024 位弱私钥对象应被拒绝，实际被接受")
	assert.True(t, strings.Contains(err.Error(), "too weak"),
		"弱私钥错误信息不符合预期: %v", err)
	assert.Contains(t, err.Error(), "RSA private key too weak",
		"错误信息应指明是私钥弱密钥（与字符串路径对齐）")

	// 公钥对象注入路径：构造必须失败
	_, err = rootcrypto.NewAsymmetric(rootcrypto.RSA, rootcrypto.WithPublicKeyObject(&weakKey.PublicKey))
	assert.Error(t, err, "1024 位弱公钥对象应被拒绝，实际被接受")
	assert.True(t, strings.Contains(err.Error(), "too weak"),
		"弱公钥错误信息不符合预期: %v", err)
	assert.Contains(t, err.Error(), "RSA public key too weak",
		"错误信息应指明是公钥弱密钥（与字符串路径对齐）")

	// 合法 2048 位对象注入不受影响（回归）
	strongKey := getTestRSAPair(t)
	_, err = rootcrypto.NewAsymmetric(rootcrypto.RSA, rootcrypto.WithPrivateKeyObject(strongKey))
	assert.NoError(t, err)
	_, err = rootcrypto.NewAsymmetric(rootcrypto.RSA, rootcrypto.WithPublicKeyObject(&strongKey.PublicKey))
	assert.NoError(t, err)
}

// ==================== RSA Name ====================

func TestRSA_Name(t *testing.T) {
	s, err := rootcrypto.NewAsymmetric(rootcrypto.RSA)
	assert.NoError(t, err)
	assert.Equal(t, "RSA", s.Name())
}

// ==================== RSA ExportPublicKey ====================

func TestRSA_ExportPublicKey(t *testing.T) {
	s, err := rootcrypto.NewAsymmetric(rootcrypto.RSA)
	assert.NoError(t, err)

	kp, err := s.GenerateKey()
	assert.NoError(t, err)
	assert.NotEmpty(t, kp.PrivateKey)

	// 仅设置私钥
	signer, err := rootcrypto.NewAsymmetric(rootcrypto.RSA, rootcrypto.WithPrivateKeyObject(kp.PrivateKey))
	assert.NoError(t, err)

	pubB64, err := signer.ExportPublicKey()
	assert.NoError(t, err)
	assert.NotEmpty(t, pubB64)

	// 用导出的公钥回读并验证签名
	verifier, err := rootcrypto.NewAsymmetric(rootcrypto.RSA, rootcrypto.WithPublicKey(pubB64))
	assert.NoError(t, err)

	msg := []byte("test export roundtrip")
	sig, err := signer.Sign(msg)
	assert.NoError(t, err)
	assert.True(t, verifier.Verify(msg, sig))
}

// TestRSA_ExportPublicKey_PublicKeyOnly：仅注入公钥时也应能导出公钥（与 ECDSA 行为对齐）。
func TestRSA_ExportPublicKey_PublicKeyOnly(t *testing.T) {
	prv := getTestRSAPair(t)

	pubBytes, err := x509.MarshalPKIXPublicKey(&prv.PublicKey)
	require.NoError(t, err)
	pubB64 := base64.StdEncoding.EncodeToString(pubBytes)

	// 仅注入公钥：ExportPublicKey 回退导出公钥
	pubOnly, err := rootcrypto.NewAsymmetric(rootcrypto.RSA, rootcrypto.WithPublicKey(pubB64))
	require.NoError(t, err)

	exported, err := pubOnly.ExportPublicKey()
	require.NoError(t, err)
	assert.Equal(t, pubB64, exported, "导出结果应与注入公钥一致")

	// 无任何密钥时仍应报错（行为不变）
	empty, err := rootcrypto.NewAsymmetric(rootcrypto.RSA)
	require.NoError(t, err)
	_, err = empty.ExportPublicKey()
	assert.Error(t, err)
}

// ==================== RSA nil key paths ====================

func TestRSA_NilKeyPaths(t *testing.T) {
	s, err := rootcrypto.NewAsymmetric(rootcrypto.RSA)
	assert.NoError(t, err)

	_, err = s.Encrypt([]byte("test"))
	assert.Error(t, err)

	_, err = s.Decrypt([]byte("test"))
	assert.Error(t, err)

	_, err = s.Sign([]byte("test"))
	assert.Error(t, err)

	assert.False(t, s.Verify([]byte("test"), []byte("sig")))
}

// ==================== RSA WithPrivateKey 无效 base64 ====================

func TestRSA_WithPrivateKey_InvalidBase64(t *testing.T) {
	_, err := rootcrypto.NewAsymmetric(rootcrypto.RSA, rootcrypto.WithPrivateKey("!!!not-base64!!!"))
	assert.Error(t, err)
}

// ==================== RSA WithPrivateKey 非 RSA 密钥 ====================

func TestRSA_WithPrivateKey_NonRSAKey(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)

	prkBytes, err := x509.MarshalPKCS8PrivateKey(ecdsaKey)
	assert.NoError(t, err)

	_, err = rootcrypto.NewAsymmetric(rootcrypto.RSA, rootcrypto.WithPrivateKey(base64.StdEncoding.EncodeToString(prkBytes)))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not an RSA private key")
}

// ==================== RSA WithPublicKey 无效 base64 ====================

func TestRSA_WithPublicKey_InvalidBase64(t *testing.T) {
	_, err := rootcrypto.NewAsymmetric(rootcrypto.RSA, rootcrypto.WithPublicKey("!!!not-base64!!!"))
	assert.Error(t, err)
}

// ==================== RSA WithPublicKey 解析错误 ====================

func TestRSA_WithPublicKey_ParserError(t *testing.T) {
	_, err := rootcrypto.NewAsymmetric(rootcrypto.RSA, rootcrypto.WithPublicKey(base64.StdEncoding.EncodeToString([]byte("not-valid-spki"))))
	assert.Error(t, err)
}

// ==================== RSA WithPublicKey 非 RSA 密钥 ====================

func TestRSA_WithPublicKey_NotRSAKey(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)

	pubBytes, err := x509.MarshalPKIXPublicKey(&ecdsaKey.PublicKey)
	assert.NoError(t, err)

	_, err = rootcrypto.NewAsymmetric(rootcrypto.RSA, rootcrypto.WithPublicKey(base64.StdEncoding.EncodeToString(pubBytes)))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not an RSA public key")
}

// ==================== RSA WithPublicKey 弱密钥 ====================

func TestRSA_WithPublicKey_WeakKey(t *testing.T) {
	weakKey, err := rsa.GenerateKey(rand.Reader, 1024)
	assert.NoError(t, err)

	pubBytes, err := x509.MarshalPKIXPublicKey(&weakKey.PublicKey)
	assert.NoError(t, err)

	_, err = rootcrypto.NewAsymmetric(rootcrypto.RSA, rootcrypto.WithPublicKey(base64.StdEncoding.EncodeToString(pubBytes)))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too weak")
}

// ==================== 共享实例失效可检测（P1 A2） ====================

func TestSharedInstance_SignAfterReset(t *testing.T) {
	kp, err := rootcrypto.GenerateKeyPair(rootcrypto.RSA)
	require.NoError(t, err)

	// NewAsymmetric 实例持有 KeyPair 同一私钥指针
	signer, err := rootcrypto.NewAsymmetric(rootcrypto.RSA, rootcrypto.WithPrivateKeyObject(kp.PrivateKey))
	require.NoError(t, err)
	// Decrypt 实例同样须在 Reset 前构造（持有同一私钥指针），
	// 才能命中 Validate 清零检测而非 nil 检查路径。
	dec, err := rootcrypto.NewAsymmetric(rootcrypto.RSA, rootcrypto.WithPrivateKeyObject(kp.PrivateKey))
	require.NoError(t, err)

	msg := []byte("before reset")
	sig, err := signer.Sign(msg)
	require.NoError(t, err)
	assert.NotEmpty(t, sig)

	// Reset 清零共享密钥后：Sign 必须返回 error，而非静默产出伪签名
	kp.Reset()
	require.NotPanics(t, func() {
		_, err = signer.Sign(msg)
	})
	assert.Error(t, err)

	// Decrypt 同理：错误信息须含 "invalid"（命中 Validate 清零检测），
	// 而非 "not set"（nil 检查）——证明验证的是 Reset 清零路径。
	require.NotPanics(t, func() {
		_, err = dec.Decrypt([]byte("ciphertext"))
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid")
	assert.NotContains(t, err.Error(), "not set")
}

// ==================== RSA 加解密（自根包 crypto_test.go 迁入） ====================

func TestRSA_SignAndVerify(t *testing.T) {
	// 生成密钥对
	rsaAlgo, err := rootcrypto.NewAsymmetric(rootcrypto.RSA)
	assert.NoError(t, err)

	keyPair, err := rsaAlgo.GenerateKey()
	assert.NoError(t, err)
	assert.NotEmpty(t, keyPair.PrivateKey)
	assert.NotEmpty(t, keyPair.PublicKey)

	// 创建新的实例并设置私钥用于签名
	signer, err := rootcrypto.NewAsymmetric(rootcrypto.RSA, rootcrypto.WithPrivateKeyObject(keyPair.PrivateKey))
	assert.NoError(t, err)

	// 签名
	message := []byte("test message")
	signature, err := signer.Sign(message)
	assert.NoError(t, err)
	assert.NotEmpty(t, signature)

	// 创建新实例设置公钥用于验证
	verifier, err := rootcrypto.NewAsymmetric(rootcrypto.RSA, rootcrypto.WithPublicKeyObject(keyPair.PublicKey))
	assert.NoError(t, err)

	// 验证
	valid := verifier.Verify(message, signature)
	assert.True(t, valid)

	// 验证错误消息
	invalid := verifier.Verify([]byte("wrong message"), signature)
	assert.False(t, invalid)
}

func TestRSA_EncryptAndDecrypt(t *testing.T) {
	// 生成密钥对
	rsaAlgo, err := rootcrypto.NewAsymmetric(rootcrypto.RSA)
	assert.NoError(t, err)

	keyPair, err := rsaAlgo.GenerateKey()
	assert.NoError(t, err)

	// 创建新实例设置密钥
	algo, err := rootcrypto.NewAsymmetric(rootcrypto.RSA, rootcrypto.WithPrivateKeyObject(keyPair.PrivateKey), rootcrypto.WithPublicKeyObject(keyPair.PublicKey))
	assert.NoError(t, err)

	// 加密
	plaintext := []byte("secret message")
	ciphertext, err := algo.Encrypt(plaintext)
	assert.NoError(t, err)
	assert.NotEqual(t, plaintext, []byte(ciphertext))

	// 解密
	decrypted, err := algo.Decrypt(ciphertext)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, []byte(decrypted))
}

// ==================== RSA 密钥位数配置消费（P3#24） ====================

// TestRSA_KeyBits_3072 WithRSAKeyBits(3072) 消费接线：GenerateKey 产出
// 3072 位密钥（BitLen==3072），且同实例签验/加解密往返通过。
func TestRSA_KeyBits_3072(t *testing.T) {
	s, err := rootcrypto.NewAsymmetric(rootcrypto.RSA, rootcrypto.WithRSAKeyBits(3072))
	require.NoError(t, err)

	kp, err := s.GenerateKey()
	require.NoError(t, err)
	rsaPrk, ok := kp.PrivateKey.(*rsa.PrivateKey)
	require.True(t, ok)
	assert.Equal(t, 3072, rsaPrk.N.BitLen(), "GenerateKey 应使用配置的 3072 位密钥")

	msg := []byte("3072-bit rsa roundtrip")
	sig, err := s.Sign(msg)
	require.NoError(t, err)
	assert.True(t, s.Verify(msg, sig), "3072 位密钥同实例签验应通过")

	ct, err := s.Encrypt([]byte("ct"))
	require.NoError(t, err)
	pt, err := s.Decrypt(ct)
	require.NoError(t, err)
	assert.Equal(t, "ct", string(pt), "3072 位密钥同实例加解密应往返")
}

// ==================== RSA 私钥字符串注入公钥回填（P3#20） ====================

// TestRSA_WithPrivateKeyString_BackfillsPublicKey 仅 WithPrivateKey(string)
// 注入私钥后，同实例可直接 Sign→Verify（公钥能力自动派生）。
func TestRSA_WithPrivateKeyString_BackfillsPublicKey(t *testing.T) {
	prv := getTestRSAPair(t)

	prkBytes, err := x509.MarshalPKCS8PrivateKey(prv)
	require.NoError(t, err)

	s, err := rootcrypto.NewAsymmetric(rootcrypto.RSA,
		rootcrypto.WithPrivateKey(base64.StdEncoding.EncodeToString(prkBytes)))
	require.NoError(t, err)

	msg := []byte("string private key backfills public key")
	sig, err := s.Sign(msg)
	require.NoError(t, err)
	assert.True(t, s.Verify(msg, sig), "WithPrivateKey(string) 后同实例验签应通过（公钥自动派生）")
}

// ==================== RSA-OAEP 锚定 KAT（P1-2） ====================
//
// crypto/rsa.EncryptOAEP 随机化（OAEP 随机 seed）→ 密文不可固定，故锚定
// Decrypt 方向：冻结一把 RSA-2048 私钥 PEM + OpenSSL 3.5.5 预生成的固定
// 密文常量（权威向量已经 OpenSSL 与 Go crypto/rsa 双向实算验证一致），
// 断言经 go-crypto RSA-OAEP 解密路径还原出期望明文。
// OAEP 的 hash 选择/label（空 []byte{}）等线上格式行为若变更，本组用例必然破坏。

// oaepKATPrivateKeyPEM 冻结的 RSA-2048 测试私钥（PKCS#8 PEM，仅供 KAT 使用，
// 严禁用于任何生产/真实密钥场景）。
const oaepKATPrivateKeyPEM = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCx3l2F3+BANubK
zs54mIsC0tYQ+Bhe8NeXFYNmXR8+N2AidC/CtFVIGvRmvxi1bE6pfuBQqSpzIRkE
7RMjNkxoRhi8Lm01iyCXrbmZJ+sl/P1s2UMBEbsRSlaAPUsk6F4KWfH+vEwCVmYr
c4LGgJoYhNjUh/3nVYtabnLTXKEPFs8q2Pm5s/Y+DPYZJPFEXQbCM+Gw2v9VPBzl
MDIUBkX0raW86z5N8dPCiD7Wk3vZlMPOY+ivVA7PjXtkSGX4/yct9hyuyk0ZaM/x
1JsBjvmhheR4s47bV4aaJ2DraD38qOX3uraJZCwrm2X2+vO5tMET9Dlhd4q/V7tn
gaeqqhKLAgMBAAECggEAA5BB7Wmz03WGIDAOgOoFdvQEZ+igjF5k41kB/e4Frzhq
y6XqQwtb3gr0NI7FjvTxioHJOrR47j+OgcPCK2VuGHS3ECYZ+AWmjINlgYUEOAme
hizAI+hYCBumKgGQXNfu8mQk7gaVu0JB38L7rsBq1ezrby6eTqEvHoux7zwe2e+B
f2CpiJIGWqPpvoGmmXqENK6Ztn0WOZvBTH+tTWxO6z/UtO7hzOs1/VRjaWMbj81c
FKiQbxbgARX+epno5QdNoUOWON8AYhZTqNz5s/xMQbvc3y/8fsL81VSxiM67rWiC
yupfzaSDQTjEfHDW+OLxXO2IrjJjbilq7xS2za1rUQKBgQDbG/rkQLRnKkx77/Uk
jfobJ3UZDWr3iwgtHQLoWjLOG31ZfJP8JHlf3jtq1slTp1hJc9fjHAMSWCSuzu/G
KdIHxVPEAhutYP9KfmykLV+Si5U7qk7+e2gzaq2kmtSc+yw3Rhxwg1kVRC9KwfFB
2XO6pfql7ffUca30QXZF0wwq0wKBgQDP0NW3pSX7vhtCgv4PkCYmcp5XV2/kK02w
83c4vmLm393VKys/FM0WyLw1VavyNMlFgyuv2s+zW+sgTkzURObNzJz8wLiEmg2L
EWfakLllhQ0zz/rzRn6Dq/X1u/RvpmXU01Dshw3Wzz3CdCVM7uTBC1anlf7oTeNG
wkloAUw2aQKBgDU/pIaKLw2PWw0XsNTUaD7nJO8UsrU8JZ2JGmbLXON4DMuNmg1B
8/lXccsyLbVVyv/21jWMXja8ExYklmLrUO6whv3woTdOhlxdQxvXJw3fPEJGznHM
HfO47kA9nIQWCpXYRRsW4LRpYLDjVzVwmk52/eYLYhpQEj11F0A63Q8fAoGAQ51T
29N830KERgiutsuUzg+e2xYUzq0UMw2T7b9sGGggGfpYsMaIz+/x5HyCXGS2U8qQ
zT+pMlcm0jUHpEzit3TqYwYlQueInoXEP4W0/IXkvMXfhYWbJiYt+Yz0w9rk6PD0
NHDgnNKC6qC1fil//hs9T3trG5Qz7VLLZW5+qHkCgYEAwEezQ3dxmmbT0o6UpsWh
GWT4d7/Tuxs38dEz1M/N8l+3rkGTbs58XPUco1zG4x9CGiq7ed6NI7wsf0oYrE2I
TpHvp4y4h15WtrbfHFRH5cGAzJ767/nyUsNk6wjKONgZzHY1JBY3vq8v38/IzXJs
Kfpc1+fPFP0j7YbiiVDsB+Q=
-----END PRIVATE KEY-----`

// oaepKATPlaintextHex 期望明文（24 字节 "go-crypto RSA-OAEP KAT 2026"）的 hex。
const oaepKATPlaintextHex = "676f2d63727970746f205253412d4f414550204b41542032303236"

// oaepKATCiphertextSHA256Hex OAEP-SHA256 固定密文（256 字节，OpenSSL 预生成）。
const oaepKATCiphertextSHA256Hex = "82159dad9ccb7b55c708c59879931084a2d85b900f7768100adfff044eceeeeda9b9cc2c0992b2f3c0bd1c1c0decd57395eabf166aeeb6b53a825175c6787bfce12958ab2ac510947e51e297a909aad23602cdf5ff1fbc18416578ed9633812774e135879cb6ef7d8593ec5955ec5915dfa62e27dd002f4b46f34386dad9e5322a7cb674a8a68b7b29c8f3b62e0ecc871f6fcdfe548546f4e4c3a355d2c95ab22f71b9c0b6e4ffafdf7a61159e7ce1fb3fcd4426f30458b4f516c5736b6810a986bc1925430d448625e87d5a061d4cf2bea87aafc57ed9bade152dff9a96f2332a9d1e19131ca2f3f30788b0c915aeee019ba0d088741ba3c981cdd549c3dd22"

// oaepKATCiphertextSHA1Hex OAEP-SHA1 固定密文（256 字节，OpenSSL 预生成，遗留互操作覆盖）。
const oaepKATCiphertextSHA1Hex = "684c821e22f050752fcebae0767716753af3ad538b700b237636c605c0c4b45d800561d8c3daf986b60f7cf62516a451d0f0f52e4ccbc442e18f205fa79647765ddb98fda9c9ce05ac6784dde5c74740065f7b87d4af6791faf2e7b8ebd82bf9c8c827995d29498f103495a22eadecda430d6a7a282104b97acd509742949d18471d2e0ad00c1a482cb00a501e9f413acb44eea1307b47bdfceb8c079d594e4522bbbb4c54214d9d7ec9f8ab3a1c82537467c3271e006965ae5a59deadfe57e84dc4c8f79b39cf7b5ca2960d22ed504a3221052c87e1d7cdcd52c4777782b0d895303f87d5256b8488194e888177bbb4df2d63562af279dfab8cc6aecf08d802"

// oaepKATPrivateKey 解析冻结的 PKCS#8 测试私钥。
func oaepKATPrivateKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	block, _ := pem.Decode([]byte(oaepKATPrivateKeyPEM))
	require.NotNil(t, block, "冻结私钥 PEM 解码失败")
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	require.NoError(t, err)
	prk, ok := key.(*rsa.PrivateKey)
	require.True(t, ok, "冻结密钥不是 RSA 私钥")
	require.Equal(t, 2048, prk.N.BitLen(), "冻结密钥应为 2048 位")
	return prk
}

// TestRSA_OAEP_KAT_SHA256：OAEP-SHA256 锚定向量。默认构造（hash=SHA256）的
// Decrypt 内部为 rsa.DecryptOAEP(sha256.New(), label=[]byte{})，与 Encrypt
// 的 EncryptOAEP 参数对齐，应还原出期望明文。
func TestRSA_OAEP_KAT_SHA256(t *testing.T) {
	prk := oaepKATPrivateKey(t)

	ct, err := hex.DecodeString(oaepKATCiphertextSHA256Hex)
	require.NoError(t, err)
	want, err := hex.DecodeString(oaepKATPlaintextHex)
	require.NoError(t, err)

	dec, err := rootcrypto.NewAsymmetric(rootcrypto.RSA, rootcrypto.WithPrivateKeyObject(prk))
	require.NoError(t, err)

	pt, err := dec.Decrypt(ct)
	require.NoError(t, err)
	assert.Equal(t, want, []byte(pt), "OAEP-SHA256 KAT：解密结果与期望明文不符")
}

// TestRSA_OAEP_KAT_SHA1：OAEP-SHA1 锚定向量（遗留互操作覆盖）。SHA-1 属
// 不安全摘要，须经 WithAsymInsecureAlgorithms() 构造期闸门显式 opt-in。
func TestRSA_OAEP_KAT_SHA1(t *testing.T) {
	prk := oaepKATPrivateKey(t)

	ct, err := hex.DecodeString(oaepKATCiphertextSHA1Hex)
	require.NoError(t, err)
	want, err := hex.DecodeString(oaepKATPlaintextHex)
	require.NoError(t, err)

	dec, err := rootcrypto.NewAsymmetric(rootcrypto.RSA,
		rootcrypto.WithPrivateKeyObject(prk),
		rootcrypto.WithAsymHash(crypto.SHA1),
		rootcrypto.WithAsymInsecureAlgorithms(),
	)
	require.NoError(t, err)

	pt, err := dec.Decrypt(ct)
	require.NoError(t, err)
	assert.Equal(t, want, []byte(pt), "OAEP-SHA1 KAT：解密结果与期望明文不符")
}
