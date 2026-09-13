package envelope

// 本文件为 RFC 9180 Seal 方向 KAT（P0-2）：在测试内用标准库自实现
// HPKE 密钥调度（LabeledExtract/LabeledExpand + DHKEM(X25519,HKDF-SHA256)
// Extract-and-Expand + Base KeySchedule + Export + ComputeNonce），复现
// §A.1.1 官方向量，并与 circl hpke.Sealer 同参数实际输出比对，闭环
// "circl 全链行为 == RFC 9180" 的 Seal 方向证明。
//
// RFC 章节纠偏（相对需求规格初稿，以 rfc-editor.org/rfc/rfc9180.txt 目录为准）：
//   - DHKEM(X25519, HKDF-SHA256) 定义在 RFC 9180 §4.1（X25519 组参数见 §4.1/§7.1）；
//   - KeySchedule 伪代码在 §5.1（Creating the Encryption Context）；
//   - Seal/nonce（ComputeNonce）在 §5.2；Export 在 §5.3；
//   - 单发射 API（Seal/Open）在 §6.1；
//   - X25519 DeriveKeyPair（sk = LabeledExpand(dkp_prk, "sk", "", Nsk)）在 §7.1.3。
//
// circl v1.6.5 API 为三段式：NewSuite → NewSender/NewReceiver → Setup →
// Seal/Open(ct 在前 aad 在后)；无 New/UnmarshalBinaryEncAndOpen。
// 确定性 enc 复现：Sender.Setup(rnd) 内部 io.ReadFull 恰好
// EncapsulationSeedSize()=32 字节 seed，喂 bytes.NewReader(ikmE) 即可。
//
// 依赖纪律：仅标准库 + circl（测试内部）+ testify；禁止引入
// golang.org/x/crypto/hkdf 作为测试直接依赖（此处 HKDF 以 crypto/hmac 手搓）。
//
// 与 P0-1 验收2 的张力说明（评审已裁定）：需求规格 P0-1 验收2 要求"circl import
// 仅保留在与官方向量无关的内部测试"，但 P0-2 决议第 2 条明确要求本文件把自实现
// 调度值与 circl hpke.Sealer 同参数输出交叉比对——二者字面冲突时以 P0-2 授权为准。
// 关键约束仍严格落实：官方向量的端到端断言只经公开 API（见 hpke_test.go，零 circl
// import），circl 在本文件仅作独立实现的一致性交叉校验，不构成对公开 API 断言的替代。

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/cloudflare/circl/hpke"
	"github.com/stretchr/testify/require"
)

// RFC 9180 §A.1.1 (mode_base, KEM=0x0020, KDF=0x0001, AEAD=0x0001) 权威向量。
const (
	katInfoHex           = "4f6465206f6e2061204772656369616e2055726e" // "Ode on a Grecian Urn"
	katIkemEHex          = "7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234"
	katPkEmHex           = "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431" // == enc
	katSkEmHex           = "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736"
	katPkRmHex           = "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d"
	katSkRmHex           = "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8"
	katSharedSecretHex   = "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc"
	katKeyHex            = "4531685d41d65f03dc48f6b8302c05b0" // AES-128 key, Nk=16
	katBaseNonceHex      = "56d890e5accaaf011cff4b7d"         // Nn=12
	katExporterSecretHex = "45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8"
	katPlaintextHex      = "4265617574792069732074727574682c20747275746820626561757479" // 29B
	// 加密序列（同一 Sealer 顺序 Seal 两个消息，seq 从 0 自增）：
	katAAD0Hex   = "436f756e742d30" // "Count-0"
	katNonce0Hex = "56d890e5accaaf011cff4b7d"
	katCT0Hex    = "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a"
	katAAD1Hex   = "436f756e742d31" // "Count-1"
	katNonce1Hex = "56d890e5accaaf011cff4b7c"
	katCT1Hex    = "af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84"
	// Export 三值（对同一 exporter_secret，非 per-seq）：
	katExportEmptyHex    = "3853fe2b4035195a573ffc53856e77058e15d9ea064de3e59f4961d0095250ee"
	katExportZeroByteHex = "2e8f0b54673c7029649d4eb9d5e33bf1872cf76d623ff164ac185da9e88c21a5" // ctx = 0x00
	katExportTestCtxHex  = "e9e43065102c3836401bed8c3c3c75ae46be1639869391d62c61f1ec7af54931" // ctx = "TestContext"
)

func katMustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err, "KAT hex 常量必须可解码: %s", s)
	return b
}

// ==================== 标准库手搓 HKDF（RFC 5869） ====================
// HMAC-SHA256 版。空 salt 时 HMAC 内部按块尺寸零填充，与 RFC 5869
// "salt 缺省为 HASHlen 个零字节" 语义一致。

func katHKDFExtract(salt, ikm []byte) []byte {
	m := hmac.New(sha256.New, salt)
	m.Write(ikm)
	return m.Sum(nil)
}

func katHKDFExpand(prk, info []byte, l int) []byte {
	var out, t []byte
	for i := byte(1); len(out) < l; i++ {
		m := hmac.New(sha256.New, prk)
		m.Write(t)
		m.Write(info)
		m.Write([]byte{i})
		t = m.Sum(nil)
		out = append(out, t...)
	}
	return out[:l]
}

// ==================== RFC 9180 Labeled KDF ====================
// suite_id: HPKE 层 = "HPKE"||I2OSP(kem_id,2)||I2OSP(kdf_id,2)||I2OSP(aead_id,2)（10B）；
// KEM 层 = "KEM"||I2OSP(kem_id,2)（5B）。

func katConcat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

var (
	katHPKESuiteID = katConcat([]byte("HPKE"), []byte{0x00, 0x20}, []byte{0x00, 0x01}, []byte{0x00, 0x01})
	katKEMSuiteID  = katConcat([]byte("KEM"), []byte{0x00, 0x20})
)

// katLabeledExtract = HKDF-Extract(salt, "HPKE-v1" || suite_id || label || ikm)
func katLabeledExtract(suiteID, salt []byte, label string, ikm []byte) []byte {
	labeledIKM := katConcat([]byte("HPKE-v1"), suiteID, []byte(label), ikm)
	return katHKDFExtract(salt, labeledIKM)
}

// katLabeledExpand = HKDF-Expand(prk, I2OSP(L,2) || "HPKE-v1" || suite_id || label || info, L)
func katLabeledExpand(prk, suiteID []byte, label string, info []byte, l int) []byte {
	labeledInfo := katConcat([]byte{byte(l >> 8), byte(l)}, []byte("HPKE-v1"), suiteID, []byte(label), info)
	return katHKDFExpand(prk, labeledInfo, l)
}

// katComputeNonce = base_nonce XOR I2OSP(seq, Nn=12)
func katComputeNonce(baseNonce []byte, seq uint64) []byte {
	nonce := make([]byte, len(baseNonce))
	copy(nonce, baseNonce)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(seq >> (8 * i))
	}
	return nonce
}

// TestHPKE_SealKAT_RFC9180 用标准库自实现密钥调度复现 RFC 9180 §A.1.1 全量
// 中间值（shared_secret/key/base_nonce/exporter_secret/三值 Export/两序列密文），
// 再与 circl hpke.Sealer 同参数实际输出逐字节比对，闭环 Seal 方向证明。
func TestHPKE_SealKAT_RFC9180(t *testing.T) {
	info := katMustHex(t, katInfoHex)
	ikmE := katMustHex(t, katIkemEHex)
	pkRm := katMustHex(t, katPkRmHex)
	skRm := katMustHex(t, katSkRmHex)
	pt := katMustHex(t, katPlaintextHex)
	aad0 := katMustHex(t, katAAD0Hex)
	aad1 := katMustHex(t, katAAD1Hex)
	ct0 := katMustHex(t, katCT0Hex)
	ct1 := katMustHex(t, katCT1Hex)

	// ---------- 0. DHKEM DeriveKeyPair(ikmE)（RFC 9180 §4.1 + §7.1.3）：由 seed 派生 skEm/pkEm ----------
	// 注意：向量中 ikmE 是种子而非 X25519 标量本身。X25519 的派生规则（§7.1.3）：
	// dkp_prk = LabeledExtract("", "dkp_prk", ikm)；sk = LabeledExpand(dkp_prk, "sk", "", Nsk=32)
	// —— context 为空串（P-256 系才带 counter 上下文）。
	dkpPRK := katLabeledExtract(katKEMSuiteID, nil, "dkp_prk", ikmE)
	skEmDerived := katLabeledExpand(dkpPRK, katKEMSuiteID, "sk", nil, 32)
	require.Equal(t, katMustHex(t, katSkEmHex), skEmDerived, "DeriveKeyPair 复现向量 skEm")

	x25519 := ecdh.X25519()
	skEmKey, err := x25519.NewPrivateKey(skEmDerived)
	require.NoError(t, err)
	pkEmDerived := skEmKey.PublicKey().Bytes()
	require.Equal(t, katMustHex(t, katPkEmHex), pkEmDerived, "pkEm 必须由派生 skEm 点乘得到（== 向量 enc）")

	skRmKey, err := x25519.NewPrivateKey(skRm)
	require.NoError(t, err)
	require.Equal(t, pkRm, skRmKey.PublicKey().Bytes(), "pkRm 必须由 skRm 派生")

	pkRmKey, err := x25519.NewPublicKey(pkRm)
	require.NoError(t, err)

	// ---------- 1. DHKEM ExtractAndExpand（RFC 9180 §4/§4.1） ----------
	enc := katMustHex(t, katPkEmHex) // 向量 enc == pkEm
	dh, err := skEmKey.ECDH(pkRmKey)
	require.NoError(t, err)
	kemContext := katConcat(enc, pkRm)
	eaePRK := katLabeledExtract(katKEMSuiteID, nil, "eae_prk", dh)
	sharedSecret := katLabeledExpand(eaePRK, katKEMSuiteID, "shared_secret", kemContext, 32)
	require.Equal(t, katMustHex(t, katSharedSecretHex), sharedSecret,
		"DHKEM ExtractAndExpand 复现 shared_secret")

	// ---------- 2. Base KeySchedule（RFC 9180 §5.1） ----------
	pskIDHash := katLabeledExtract(katHPKESuiteID, nil, "psk_id_hash", nil)
	infoHash := katLabeledExtract(katHPKESuiteID, nil, "info_hash", info)
	ksc := katConcat([]byte{0x00}, pskIDHash, infoHash) // mode_base
	secret := katLabeledExtract(katHPKESuiteID, sharedSecret, "secret", nil)
	key := katLabeledExpand(secret, katHPKESuiteID, "key", ksc, 16)
	baseNonce := katLabeledExpand(secret, katHPKESuiteID, "base_nonce", ksc, 12)
	exporterSecret := katLabeledExpand(secret, katHPKESuiteID, "exp", ksc, 32)
	require.Equal(t, katMustHex(t, katKeyHex), key, "KeySchedule 复现 key（AES-128）")
	require.Equal(t, katMustHex(t, katBaseNonceHex), baseNonce, "KeySchedule 复现 base_nonce")
	require.Equal(t, katMustHex(t, katExporterSecretHex), exporterSecret, "KeySchedule 复现 exporter_secret")

	// ---------- 3. 自实现 AEAD 加密序列（§5.2 Seal + ComputeNonce） ----------
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)
	require.Equal(t, katMustHex(t, katNonce0Hex), katComputeNonce(baseNonce, 0))
	require.Equal(t, katMustHex(t, katNonce1Hex), katComputeNonce(baseNonce, 1))
	selfCT0 := gcm.Seal(nil, katComputeNonce(baseNonce, 0), pt, aad0)
	selfCT1 := gcm.Seal(nil, katComputeNonce(baseNonce, 1), pt, aad1)
	require.Equal(t, ct0, selfCT0, "自实现 seq0 密文 == 官方向量")
	require.Equal(t, ct1, selfCT1, "自实现 seq1 密文 == 官方向量")

	// ---------- 4. 自实现 Export（§5.3：LabeledExpand(exporter_secret, "sec", ctx)） ----------
	require.Equal(t, katMustHex(t, katExportEmptyHex),
		katLabeledExpand(exporterSecret, katHPKESuiteID, "sec", nil, 32), `Export("", 32)`)
	require.Equal(t, katMustHex(t, katExportZeroByteHex),
		katLabeledExpand(exporterSecret, katHPKESuiteID, "sec", []byte{0x00}, 32), `Export(0x00, 32)`)
	require.Equal(t, katMustHex(t, katExportTestCtxHex),
		katLabeledExpand(exporterSecret, katHPKESuiteID, "sec", []byte("TestContext"), 32), `Export("TestContext", 32)`)

	// ---------- 5. circl 三段式 Seal 方向比对（确定性 enc 复现 + 同参数输出一致） ----------
	suited := hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
	kemScheme := hpke.KEM_X25519_HKDF_SHA256.Scheme()
	circlPkR, err := kemScheme.UnmarshalBinaryPublicKey(pkRm)
	require.NoError(t, err)
	sender, err := suited.NewSender(circlPkR, info)
	require.NoError(t, err)

	// Setup 内部 io.ReadFull 恰好 32B seed（= ikmE），经 DeriveKeyPair 派生临时密钥；
	// 喂 bytes.NewReader(ikmE) 即可复现确定性 enc == pkEm。
	circlEnc, sealer, err := sender.Setup(bytes.NewReader(ikmE))
	require.NoError(t, err)
	require.Equal(t, enc, circlEnc, "circl 以 ikmE 为 seed 复现向量 enc")

	// 同一 Sealer 顺序 Seal 两消息（seq 内部自增），输出须与官方向量逐字节一致。
	circlCT0, err := sealer.Seal(pt, aad0)
	require.NoError(t, err)
	require.Equal(t, ct0, circlCT0, "circl Seal seq0 == 官方向量 == 自实现调度产物")
	circlCT1, err := sealer.Seal(pt, aad1)
	require.NoError(t, err)
	require.Equal(t, ct1, circlCT1, "circl Seal seq1 == 官方向量 == 自实现调度产物")

	// circl Export 三值 == 官方向量。
	require.Equal(t, katMustHex(t, katExportEmptyHex), sealer.Export([]byte{}, 32), `circl Export("", 32)`)
	require.Equal(t, katMustHex(t, katExportZeroByteHex), sealer.Export([]byte{0x00}, 32), `circl Export(0x00, 32)`)
	require.Equal(t, katMustHex(t, katExportTestCtxHex), sealer.Export([]byte("TestContext"), 32), `circl Export("TestContext", 32)`)

	// ---------- 6. circl 接收侧与自实现 KeySchedule 的对称性（Receiver 导出比对） ----------
	circlSkR, err := kemScheme.UnmarshalBinaryPrivateKey(skRm)
	require.NoError(t, err)
	receiver, err := suited.NewReceiver(circlSkR, info)
	require.NoError(t, err)
	opener, err := receiver.Setup(enc)
	require.NoError(t, err)
	require.Equal(t, katMustHex(t, katExportEmptyHex), opener.Export([]byte{}, 32),
		"Receiver 侧 exporter_secret 与 Sender/自实现一致")
}

// TestHPKESealWithAAD_RoundTrip 验证新增公开 API 的基本往返与非空 aad 绑定。
func TestHPKESealWithAAD_RoundTrip(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	pub := priv.PublicKey()

	pt := []byte("aad-bound payload")
	info := []byte("ctx")
	aad := []byte("version-keyid-binding")

	enc, ct, err := HPKESealWithAAD(HPKE_X25519_HKDF_SHA256_AES_256_GCM, pub, pt, aad, info)
	require.NoError(t, err)

	got, err := HPKEOpenWithAAD(HPKE_X25519_HKDF_SHA256_AES_256_GCM, priv, enc, ct, aad, info)
	require.NoError(t, err)
	require.Equal(t, pt, got)

	// aad 不匹配 → ErrHPKEOpenFailed
	_, err = HPKEOpenWithAAD(HPKE_X25519_HKDF_SHA256_AES_256_GCM, priv, enc, ct, []byte("other"), info)
	require.ErrorIs(t, err, ErrHPKEOpenFailed)
}
