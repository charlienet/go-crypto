package crypto_test

// 根包契约用例（package crypto_test，blank import symmetric 触发引擎注册）：
// 枚举/String/Parse/BlockSize/KeySize/哨兵/密钥源覆盖/选项×模式校验/
// 选项应用一次/nil 选项等。六模式往返类用例已迁 crypto/symmetric/executor_test.go。
// 断言文本与迁移前 encrypt_test.go 完全一致。

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/charlienet/go-crypto"

	_ "github.com/charlienet/go-crypto/symmetric"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==================== 枚举：String/Parse 往返 ====================

func TestAlgorithm_String_Parse_RoundTrip(t *testing.T) {
	algs := []crypto.Algorithm{crypto.AES128, crypto.AES192, crypto.AES256, crypto.SM4, crypto.DES, crypto.TripleDES}
	wantNames := []string{"AES-128", "AES-192", "AES-256", "SM4", "DES", "3DES"}
	for i, a := range algs {
		assert.Equal(t, wantNames[i], a.String(), "Algorithm.String()")
		parsed, err := crypto.ParseAlgorithm(a.String())
		require.NoError(t, err)
		assert.Equal(t, a, parsed, "ParseAlgorithm(String()) 往返")
	}

	// 别名：大小写不敏感、忽略连字符
	aliases := []struct {
		name string
		want crypto.Algorithm
	}{
		{"aes128", crypto.AES128}, {"aes-128", crypto.AES128}, {"AES128", crypto.AES128}, {"AES-128", crypto.AES128},
		{"aes192", crypto.AES192}, {"AES192", crypto.AES192},
		{"aes256", crypto.AES256}, {"AES-256", crypto.AES256},
		{"sm4", crypto.SM4}, {"SM4", crypto.SM4},
		{"des", crypto.DES}, {"DES", crypto.DES},
		{"3des", crypto.TripleDES}, {"3DES", crypto.TripleDES}, {"tripledes", crypto.TripleDES}, {"TripleDES", crypto.TripleDES},
	}
	for _, c := range aliases {
		got, err := crypto.ParseAlgorithm(c.name)
		require.NoError(t, err, "ParseAlgorithm(%q)", c.name)
		assert.Equal(t, c.want, got)
	}
}

func TestMode_String_Parse_RoundTrip(t *testing.T) {
	modes := []crypto.Mode{crypto.ECB, crypto.CBC, crypto.CTR, crypto.CFB, crypto.OFB, crypto.GCM}
	wantNames := []string{"ECB", "CBC", "CTR", "CFB", "OFB", "GCM"}
	for i, m := range modes {
		assert.Equal(t, wantNames[i], m.String(), "Mode.String()")
		parsed, err := crypto.ParseMode(m.String())
		require.NoError(t, err)
		assert.Equal(t, m, parsed, "ParseMode(String()) 往返")
	}

	// 别名：大小写不敏感
	for _, name := range []string{"ecb", "cbc", "ctr", "cfb", "ofb", "gcm"} {
		_, err := crypto.ParseMode(name)
		require.NoError(t, err, "ParseMode(%q)", name)
	}
}

func TestParse_Unknown(t *testing.T) {
	_, err := crypto.ParseAlgorithm("AES-999")
	assert.ErrorIs(t, err, crypto.ErrUnknownAlgorithm)
	_, err = crypto.ParseAlgorithm("")
	assert.ErrorIs(t, err, crypto.ErrUnknownAlgorithm)

	_, err = crypto.ParseMode("XYZ")
	assert.ErrorIs(t, err, crypto.ErrUnknownMode)
	_, err = crypto.ParseMode("")
	assert.ErrorIs(t, err, crypto.ErrUnknownMode)
}

func TestAlgorithm_BlockSize_KeySize(t *testing.T) {
	cases := []struct {
		alg       crypto.Algorithm
		blockSize int
		keySize   int
	}{
		{crypto.AES128, 16, 16},
		{crypto.AES192, 16, 24},
		{crypto.AES256, 16, 32},
		{crypto.SM4, 16, 16},
		{crypto.DES, 8, 8},
		{crypto.TripleDES, 8, 24},
	}
	for _, c := range cases {
		assert.Equal(t, c.blockSize, c.alg.BlockSize(), "%s BlockSize", c.alg)
		assert.Equal(t, c.keySize, c.alg.KeySize(), "%s KeySize", c.alg)
	}
}

// ==================== IV：长度校验 ====================

func TestWithIV_LengthMismatch(t *testing.T) {
	key := make([]byte, 16)

	// 15B IV × AES128-CBC（期望 16B）→ ErrInvalidIVLength
	_, err := crypto.Encrypt(crypto.AES128, crypto.CBC, []byte("data"), crypto.WithKey(key), crypto.WithIV(make([]byte, 15)))
	assert.ErrorIs(t, err, crypto.ErrInvalidIVLength)

	// ECB 传 IV → ErrIVNotSupported
	_, err = crypto.Encrypt(crypto.AES128, crypto.ECB, []byte("data"), crypto.WithKey(key), crypto.WithIV(make([]byte, 16)), crypto.WithInsecureAlgorithms())
	assert.ErrorIs(t, err, crypto.ErrIVNotSupported)

	// GCM 传 IV → ErrIVNotSupported
	_, err = crypto.Encrypt(crypto.AES128, crypto.GCM, []byte("data"), crypto.WithKey(key), crypto.WithIV(make([]byte, 16)))
	assert.ErrorIs(t, err, crypto.ErrIVNotSupported)
}

// ==================== 选项×模式不兼容 ====================

func TestOptionModeIncompat(t *testing.T) {
	key := make([]byte, 16)

	// GCM × WithPadding → ErrPaddingNotSupported
	_, err := crypto.Encrypt(crypto.AES128, crypto.GCM, []byte("x"), crypto.WithKey(key), crypto.WithPadding(crypto.NoPadding{}))
	assert.ErrorIs(t, err, crypto.ErrPaddingNotSupported)

	// CTR × WithPadding → ErrPaddingNotSupported
	_, err = crypto.Encrypt(crypto.AES128, crypto.CTR, []byte("x"), crypto.WithKey(key), crypto.WithPadding(crypto.NoPadding{}))
	assert.ErrorIs(t, err, crypto.ErrPaddingNotSupported)

	// CBC × WithAAD → ErrAADNotSupported
	_, err = crypto.Encrypt(crypto.AES128, crypto.CBC, []byte("x"), crypto.WithKey(key), crypto.WithAAD([]byte("aad")))
	assert.ErrorIs(t, err, crypto.ErrAADNotSupported)

	// CFB × WithAAD → ErrAADNotSupported
	_, err = crypto.Encrypt(crypto.AES128, crypto.CFB, []byte("x"), crypto.WithKey(key), crypto.WithAAD([]byte("aad")))
	assert.ErrorIs(t, err, crypto.ErrAADNotSupported)

	// GCM × WithAAD 正常（受支持）
	_, err = crypto.Encrypt(crypto.AES128, crypto.GCM, []byte("x"), crypto.WithKey(key), crypto.WithAAD([]byte("aad")))
	assert.NoError(t, err)
}

// ==================== 审核修复：EmbedIV/EmbedNonce 矛盾组合（P3#21） ====================

// TestEmbedOptionConflicts 嵌入式选项与显式 IV/nonce 的矛盾校验：
//   - EmbedIV + WithIV、EmbedNonce + WithNonce → ErrEmbedConflict（×2）
//   - EmbedNonce 配非 GCM 模式 → ErrNonceNotSupported（×2）
//   - EmbedIV 配 ECB/GCM → ErrIVNotSupported（×2）
//   - 单独 EmbedIV()/EmbedNonce()（无 IV/Nonce）为合法 no-op（×1）
func TestEmbedOptionConflicts(t *testing.T) {
	key := make([]byte, 16)

	// 矛盾组合 ×2：嵌入选项与显式值语义冲突
	_, err := crypto.Encrypt(crypto.AES128, crypto.CBC, []byte("x"), crypto.WithKey(key), crypto.EmbedIV(), crypto.WithIV(make([]byte, 16)))
	assert.ErrorIs(t, err, crypto.ErrEmbedConflict, "EmbedIV+WithIV 应报 ErrEmbedConflict")

	_, err = crypto.Encrypt(crypto.AES128, crypto.GCM, []byte("x"), crypto.WithKey(key), crypto.EmbedNonce(), crypto.WithNonce(make([]byte, 12)))
	assert.ErrorIs(t, err, crypto.ErrEmbedConflict, "EmbedNonce+WithNonce 应报 ErrEmbedConflict")

	// 模式错配 ×2：EmbedNonce 仅 GCM、EmbedIV 不适用 ECB（无 IV）
	_, err = crypto.Encrypt(crypto.AES128, crypto.CBC, []byte("x"), crypto.WithKey(key), crypto.EmbedNonce())
	assert.ErrorIs(t, err, crypto.ErrNonceNotSupported, "EmbedNonce×CBC 应报 ErrNonceNotSupported")

	_, err = crypto.Encrypt(crypto.AES128, crypto.CFB, []byte("x"), crypto.WithKey(key), crypto.EmbedNonce())
	assert.ErrorIs(t, err, crypto.ErrNonceNotSupported, "EmbedNonce×CFB 应报 ErrNonceNotSupported")

	// EmbedIV 配 GCM（nonce 专属）与 ECB（无 IV）复用 ErrIVNotSupported
	_, err = crypto.Encrypt(crypto.AES128, crypto.GCM, []byte("x"), crypto.WithKey(key), crypto.EmbedIV())
	assert.ErrorIs(t, err, crypto.ErrIVNotSupported, "EmbedIV×GCM 应报 ErrIVNotSupported")

	_, err = crypto.Encrypt(crypto.AES128, crypto.ECB, []byte("x"), crypto.WithKey(key), crypto.EmbedIV(), crypto.WithInsecureAlgorithms())
	assert.ErrorIs(t, err, crypto.ErrIVNotSupported, "EmbedIV×ECB 应报 ErrIVNotSupported")

	// 单独使用：无显式 IV/Nonce 时嵌入选项为合法 no-op
	//（协议层默认即随机生成并前置，加密成功即证明放行）
	for _, tc := range []struct {
		mode  crypto.Mode
		embed crypto.Option
		name  string
	}{
		{crypto.CBC, crypto.EmbedIV(), "EmbedIV only × CBC"},
		{crypto.GCM, crypto.EmbedNonce(), "EmbedNonce only × GCM"},
	} {
		opts := []crypto.Option{crypto.WithKey(key), tc.embed}
		ct, err := crypto.Encrypt(crypto.AES128, tc.mode, []byte("x"), opts...)
		require.NoError(t, err, "%s 应合法", tc.name)
		_, err = crypto.Decrypt(crypto.AES128, tc.mode, ct, opts...)
		require.NoError(t, err, "%s 解密应对称成功", tc.name)
	}
}

// ==================== 密钥四源 ====================

func TestKeySources(t *testing.T) {
	key := []byte("0123456789abcdef") // 16B
	pt := []byte("key source test")
	alg, mode := crypto.AES128, crypto.GCM

	// 四源分别可加密
	ctKey, err := crypto.Encrypt(alg, mode, pt, crypto.WithKey(key))
	require.NoError(t, err)
	ctPass, err := crypto.Encrypt(alg, mode, pt, crypto.WithKeyPassword(string(key)))
	require.NoError(t, err)
	ctHex, err := crypto.Encrypt(alg, mode, pt, crypto.WithHexPassword(hex.EncodeToString(key)))
	require.NoError(t, err)
	ctB64, err := crypto.Encrypt(alg, mode, pt, crypto.WithBase64Password(base64.StdEncoding.EncodeToString(key)))
	require.NoError(t, err)

	// 互解：任一源加密的密文可用任一源解密
	decryptAll := func(ct []byte, src string) {
		_, err := crypto.Decrypt(alg, mode, ct, crypto.WithKey(key))
		require.NoError(t, err, "%s 密文用 WithKey 解密", src)
		_, err = crypto.Decrypt(alg, mode, ct, crypto.WithKeyPassword(string(key)))
		require.NoError(t, err, "%s 密文用 WithKeyPassword 解密", src)
		_, err = crypto.Decrypt(alg, mode, ct, crypto.WithHexPassword(hex.EncodeToString(key)))
		require.NoError(t, err, "%s 密文用 WithHexPassword 解密", src)
		_, err = crypto.Decrypt(alg, mode, ct, crypto.WithBase64Password(base64.StdEncoding.EncodeToString(key)))
		require.NoError(t, err, "%s 密文用 WithBase64Password 解密", src)
	}
	decryptAll(ctKey, "WithKey")
	decryptAll(ctPass, "WithKeyPassword")
	decryptAll(ctHex, "WithHexPassword")
	decryptAll(ctB64, "WithBase64Password")

	// 测试覆盖行为：第二个选项覆盖第一个
	// 用 WithKeyPassword 覆盖 WithKey
	pw := string(key)
	ct, err := crypto.Encrypt(alg, mode, pt, crypto.WithKey([]byte("wrong_key")), crypto.WithKeyPassword(pw))
	assert.NoError(t, err)
	got, err := crypto.Decrypt(alg, mode, ct, crypto.WithKeyPassword(pw))
	assert.NoError(t, err)
	assert.Equal(t, pt, got)

	// 用 WithBase64Password 覆盖 WithHexPassword
	b64 := base64.StdEncoding.EncodeToString(key)
	ct2, err := crypto.Encrypt(alg, mode, pt, crypto.WithHexPassword(hex.EncodeToString([]byte("wrong_key"))), crypto.WithBase64Password(b64))
	assert.NoError(t, err)
	got2, err := crypto.Decrypt(alg, mode, ct2, crypto.WithBase64Password(b64))
	assert.NoError(t, err)
	assert.Equal(t, pt, got2)

	// 全无 → ErrKeyRequired
	_, err = crypto.Encrypt(alg, mode, pt)
	assert.ErrorIs(t, err, crypto.ErrKeyRequired)
	_, err = crypto.Decrypt(alg, mode, []byte("x"))
	assert.ErrorIs(t, err, crypto.ErrKeyRequired)

	// 坏 hex → ErrInvalidHexPassword
	_, err = crypto.Encrypt(alg, mode, pt, crypto.WithHexPassword("zz"))
	assert.ErrorIs(t, err, crypto.ErrInvalidHexPassword)

	// 坏 base64 → ErrInvalidBase64Password
	_, err = crypto.Encrypt(alg, mode, pt, crypto.WithBase64Password("!!!not-base64!!!"))
	assert.ErrorIs(t, err, crypto.ErrInvalidBase64Password)
}

// ==================== 密钥长度严格校验 ====================

func TestKeyLengthStrict(t *testing.T) {
	// AES256 + 16B 密钥 → NewCipher 长度错误
	_, err := crypto.Encrypt(crypto.AES256, crypto.GCM, []byte("data"), crypto.WithKey(make([]byte, 16)))
	assert.Error(t, err)

	cases := []struct {
		alg crypto.Algorithm
		key []byte
		ok  bool
	}{
		{crypto.AES128, make([]byte, 16), true},
		{crypto.AES128, make([]byte, 15), false},
		{crypto.AES192, make([]byte, 24), true},
		{crypto.AES192, make([]byte, 16), false},
		{crypto.AES256, make([]byte, 32), true},
		{crypto.SM4, make([]byte, 16), true},
		{crypto.SM4, make([]byte, 15), false},
		{crypto.DES, make([]byte, 8), true},
		{crypto.DES, make([]byte, 7), false},
		{crypto.TripleDES, make([]byte, 24), true},
		{crypto.TripleDES, make([]byte, 16), false},
	}
	for _, c := range cases {
		_, err := crypto.Encrypt(c.alg, crypto.ECB, []byte("data"), crypto.WithKey(c.key), crypto.WithInsecureAlgorithms())
		if c.ok {
			assert.NoError(t, err, "%s 密钥长度 %d 应通过", c.alg, len(c.key))
		} else {
			assert.Error(t, err, "%s 密钥长度 %d 应被拒绝", c.alg, len(c.key))
		}
	}
}

// ==================== 审核修复：非法枚举值返回明确哨兵（P3） ====================

func TestEncrypt_InvalidEnum(t *testing.T) {
	key := make([]byte, 16)
	pt := []byte("data")

	// 非法算法：0/255 → ErrUnknownAlgorithm
	_, err := crypto.Encrypt(crypto.Algorithm(0), crypto.GCM, pt, crypto.WithKey(key))
	assert.ErrorIs(t, err, crypto.ErrUnknownAlgorithm)
	_, err = crypto.Encrypt(crypto.Algorithm(255), crypto.GCM, pt, crypto.WithKey(key))
	assert.ErrorIs(t, err, crypto.ErrUnknownAlgorithm)

	// 非法模式：0/255 → ErrUnknownMode
	_, err = crypto.Encrypt(crypto.AES128, crypto.Mode(0), pt, crypto.WithKey(key))
	assert.ErrorIs(t, err, crypto.ErrUnknownMode)
	_, err = crypto.Encrypt(crypto.AES128, crypto.Mode(255), pt, crypto.WithKey(key))
	assert.ErrorIs(t, err, crypto.ErrUnknownMode)

	// 携带选项时校验顺序：枚举范围优先于选项×模式校验与密钥解析
	_, err = crypto.Encrypt(crypto.AES128, crypto.Mode(99), pt, crypto.WithKey(key), crypto.WithNonce(make([]byte, 12)))
	assert.ErrorIs(t, err, crypto.ErrUnknownMode, "非法模式应先于 ErrNonceNotSupported")
	_, err = crypto.Encrypt(crypto.Algorithm(0), crypto.GCM, pt, crypto.WithKey(key), crypto.WithHexPassword("zz"))
	assert.ErrorIs(t, err, crypto.ErrUnknownAlgorithm, "非法算法应先于 ErrInvalidHexPassword")

	// 解密同样适用
	_, err = crypto.Decrypt(crypto.Algorithm(0), crypto.GCM, []byte("x"), crypto.WithKey(key))
	assert.ErrorIs(t, err, crypto.ErrUnknownAlgorithm)
	_, err = crypto.Decrypt(crypto.AES128, crypto.Mode(0), []byte("x"), crypto.WithKey(key))
	assert.ErrorIs(t, err, crypto.ErrUnknownMode)
}

// ==================== 审核修复：密钥长度错误哨兵（P4） ====================

func TestInvalidKeyLength_Sentinel(t *testing.T) {
	// AES 三档错误密钥 → ErrInvalidKeyLength（errors.Is 可识别）
	cases := []struct {
		alg string
		key []byte
	}{
		{"AES-128", make([]byte, 15)},
		{"AES-128", make([]byte, 17)},
		{"AES-192", make([]byte, 16)},
		{"AES-256", make([]byte, 16)},
		{"AES-256", make([]byte, 31)},
	}
	for _, c := range cases {
		_, err := crypto.NewCipher(c.alg, c.key)
		assert.ErrorIs(t, err, crypto.ErrInvalidKeyLength, "%s %dB", c.alg, len(c.key))
	}

	// 泛名 "AES" 非法长度同样可识别
	_, err := crypto.NewCipher("AES", make([]byte, 15))
	assert.ErrorIs(t, err, crypto.ErrInvalidKeyLength)

	// 模式化 API 层透传同一哨兵
	_, err = crypto.Encrypt(crypto.AES256, crypto.GCM, []byte("data"), crypto.WithKey(make([]byte, 16)))
	assert.ErrorIs(t, err, crypto.ErrInvalidKeyLength)

	// 合法密钥不触发
	_, err = crypto.NewCipher("AES-128", make([]byte, 16))
	require.NoError(t, err)
}

// ==================== 审核修复：nil IV/nonce 语义（P7） ====================

func TestNilIVNonce_Semantics(t *testing.T) {
	key := make([]byte, 16)
	pt := []byte("nil option semantics")

	// WithIV(nil) 等价于未提供：默认随机 IV + 前置
	ctNil, err := crypto.Encrypt(crypto.AES128, crypto.CBC, pt, crypto.WithKey(key), crypto.WithIV(nil))
	require.NoError(t, err)
	ctDefault, err := crypto.Encrypt(crypto.AES128, crypto.CBC, pt, crypto.WithKey(key))
	require.NoError(t, err)
	assert.Equal(t, len(ctDefault), len(ctNil), "WithIV(nil) 应与未传一致（含 IV 前缀）")
	pt2, err := crypto.Decrypt(crypto.AES128, crypto.CBC, ctNil, crypto.WithKey(key))
	require.NoError(t, err)
	assert.Equal(t, pt, pt2)

	// WithNonce(nil) 等价于未提供：默认随机 nonce + 前置
	gcmNil, err := crypto.Encrypt(crypto.AES128, crypto.GCM, pt, crypto.WithKey(key), crypto.WithNonce(nil))
	require.NoError(t, err)
	gcmDefault, err := crypto.Encrypt(crypto.AES128, crypto.GCM, pt, crypto.WithKey(key))
	require.NoError(t, err)
	assert.Equal(t, len(gcmDefault), len(gcmNil), "WithNonce(nil) 应与未传一致（含 nonce 前缀）")
	assert.Equal(t, len(pt)+28, len(gcmNil), "GCM 默认路径含 12B nonce + 16B tag")
	pt3, err := crypto.Decrypt(crypto.AES128, crypto.GCM, gcmNil, crypto.WithKey(key))
	require.NoError(t, err)
	assert.Equal(t, pt, pt3)
}

// ==================== 审核修复：选项仅应用一次（P8） ====================

func TestOptionAppliedOnce(t *testing.T) {
	key := make([]byte, 16)
	pt := []byte("option applied once")

	count := 0
	counterOpt := crypto.Option(func(cfg *crypto.Config) { count++ })

	// 携带自定义计数选项加密：应恰好应用一次（resolveKey/validateModeOpts 不再重复应用）
	ct, err := crypto.Encrypt(crypto.AES128, crypto.GCM, pt, crypto.WithKey(key), counterOpt)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "Encrypt 中选项应仅应用一次")

	// 解密同样仅应用一次
	count = 0
	_, err = crypto.Decrypt(crypto.AES128, crypto.GCM, ct, crypto.WithKey(key), counterOpt)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "Decrypt 中选项应仅应用一次")

	// 多选项混合：每个选项各应用一次
	count = 0
	_, err = crypto.Encrypt(crypto.AES128, crypto.GCM, pt, crypto.WithKey(key), counterOpt, counterOpt)
	require.NoError(t, err)
	assert.Equal(t, 2, count, "两个选项应各应用一次")
}

// ==================== 审核修复：ZeroPadding 全对齐返回独立拷贝（P9） ====================

func TestZeroPadding_AlignedCopy(t *testing.T) {
	src := []byte("0123456789abcdef") // 16B 全对齐

	out, err := (crypto.ZeroPadding{}).Padding(16, src)
	require.NoError(t, err)
	require.Equal(t, src, out)

	// 修改输入后返回值必须不受影响（不与输入共享底层数组）
	src[0] = 'X'
	assert.Equal(t, []byte("0123456789abcdef"), out, "Padding 返回值不应与输入共享底层")
}

// ==================== 审核修复：nil Option 安全（低-1） ====================

func TestNilOption_Safe(t *testing.T) {
	key := make([]byte, 16)
	iv := make([]byte, 16)
	pt := []byte("nil option safe")

	// 模式化 API：nil Option 不 panic
	ct, err := crypto.Encrypt(crypto.AES128, crypto.GCM, pt, crypto.WithKey(key), nil)
	require.NoError(t, err)
	_, err = crypto.Decrypt(crypto.AES128, crypto.GCM, ct, crypto.WithKey(key), nil)
	require.NoError(t, err)

	// 低层构造：nil Option 不 panic
	c, err := crypto.NewCipher("AES", key)
	require.NoError(t, err)
	_, err = c.NewGCM(nil, nil, crypto.EmbedNonce())
	require.NoError(t, err)
	_, err = c.NewCBC(iv, nil)
	require.NoError(t, err)
	_, err = c.NewECB(nil, crypto.WithInsecureAlgorithms())
	require.NoError(t, err)
	_, err = c.NewCFB(iv, nil)
	require.NoError(t, err)
	_, err = c.NewOFB(iv, nil)
	require.NoError(t, err)

	// AADFromOptions 对 nil Option 安全
	assert.Nil(t, crypto.AADFromOptions(nil, nil))
}
