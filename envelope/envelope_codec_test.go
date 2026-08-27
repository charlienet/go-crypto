package envelope

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rootcrypto "github.com/charlienet/go-crypto"
)

// nameOnlyCodec 仅用于注册表测试：Name() 可定制，Encrypt/Decrypt 为占位实现。
type nameOnlyCodec struct{ name string }

func (c nameOnlyCodec) Name() string { return c.name }
func (c nameOnlyCodec) Encrypt(rootcrypto.Algorithm, []byte, []byte, ...rootcrypto.Option) ([]byte, error) {
	return nil, nil
}
func (c nameOnlyCodec) Decrypt([]byte, []byte, ...rootcrypto.Option) ([]byte, error) {
	return nil, nil
}

// legacyECBCodec 测试用示例适配器：演示应用侧自加"格式翻译"底层。
// 布局：AES-ECB（默认 PKCS7 填充）+ Base64 编码；无自描述头，解密固定 AES-128。
// 注意：ECB 无认证，仅演示适配器接入机制，切勿用于真实安全场景。
type legacyECBCodec struct{}

func (legacyECBCodec) Name() string { return "test-legacy-ecb" }

func (legacyECBCodec) Encrypt(algorithm rootcrypto.Algorithm, key []byte, plaintext []byte, opts ...rootcrypto.Option) ([]byte, error) {
	c, err := rootcrypto.NewCipher(algorithm.String(), key)
	if err != nil {
		return nil, err
	}
	mode, err := c.NewECB()
	if err != nil {
		return nil, err
	}
	ct, err := mode.Encrypt(plaintext)
	if err != nil {
		return nil, err
	}
	return []byte(base64.StdEncoding.EncodeToString(ct)), nil
}

func (legacyECBCodec) Decrypt(key []byte, envelope []byte, opts ...rootcrypto.Option) ([]byte, error) {
	ct, err := base64.StdEncoding.DecodeString(string(envelope))
	if err != nil {
		return nil, fmt.Errorf("test-legacy-ecb: 非法 Base64 密文: %w", err)
	}
	c, err := rootcrypto.NewCipher("AES-128", key)
	if err != nil {
		return nil, err
	}
	mode, err := c.NewECB()
	if err != nil {
		return nil, err
	}
	return mode.Decrypt(ct)
}

// ==================== 注册表 ====================

func TestRegisterEnvelopeCodec_Success(t *testing.T) {
	err := RegisterEnvelopeCodec(nameOnlyCodec{name: "test-codec-a"})
	assert.NoError(t, err)

	got, err := EnvelopeCodecByName("test-codec-a")
	assert.NoError(t, err)
	assert.Equal(t, "test-codec-a", got.Name())
}

func TestRegisterEnvelopeCodec_DuplicateName(t *testing.T) {
	// 自定义名重复注册 → 拒绝且不覆盖
	err := RegisterEnvelopeCodec(nameOnlyCodec{name: "test-dup-custom"})
	require.NoError(t, err)
	err = RegisterEnvelopeCodec(nameOnlyCodec{name: "test-dup-custom"})
	assert.ErrorIs(t, err, ErrEnvelopeCodecExists)

	// 保留名 "gcx1" 不可被应用侧覆盖
	err = RegisterEnvelopeCodec(nameOnlyCodec{name: EnvelopeCodecGCX1})
	assert.ErrorIs(t, err, ErrEnvelopeCodecExists)
}

func TestRegisterEnvelopeCodec_InvalidName(t *testing.T) {
	longName := string(bytes.Repeat([]byte{'a'}, 65))
	tests := []struct {
		desc string
		name string
		want error
	}{
		{"空名（Name 为空命中专门校验）", "", ErrInvalidEnvelopeCodec},
		{"首字符大写", "Bad", ErrInvalidEnvelopeCodecName},
		{"首字符数字", "1abc", ErrInvalidEnvelopeCodecName},
		{"含空格", "a b", ErrInvalidEnvelopeCodecName},
		{"超长 65 字符", longName, ErrInvalidEnvelopeCodecName},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			err := RegisterEnvelopeCodec(nameOnlyCodec{name: tt.name})
			assert.ErrorIs(t, err, tt.want)
		})
	}
}

func TestRegisterEnvelopeCodec_Nil(t *testing.T) {
	err := RegisterEnvelopeCodec(nil)
	assert.ErrorIs(t, err, ErrInvalidEnvelopeCodec)
}

func TestRegisterEnvelopeCodec_TypedNilPointer(t *testing.T) {
	// 类型化 nil 指针：codec == nil 为 false（接口持有类型信息），
	// 但调用 Name() 会 panic。必须被防护识别并返回 ErrInvalidEnvelopeCodec。
	var codec *nameOnlyCodec
	err := RegisterEnvelopeCodec(codec)
	assert.ErrorIs(t, err, ErrInvalidEnvelopeCodec)
}

func TestEnvelopeCodecByName_Unknown(t *testing.T) {
	_, err := EnvelopeCodecByName("no-such-codec")
	assert.ErrorIs(t, err, ErrUnknownEnvelopeCodec)
}

func TestEnvelopeCodecByName_GCX1Default(t *testing.T) {
	// 内置 codec 无需注册即可查到（默认兜底）
	codec, err := EnvelopeCodecByName(EnvelopeCodecGCX1)
	require.NoError(t, err)
	assert.Equal(t, EnvelopeCodecGCX1, codec.Name())
}

func TestRegisterEnvelopeCodec_Concurrent(t *testing.T) {
	const n = 10
	var wg sync.WaitGroup

	// 并发注册不同名
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := fmt.Sprintf("test-conc-%d", i)
			err := RegisterEnvelopeCodec(nameOnlyCodec{name: name})
			assert.NoError(t, err)
		}(i)
	}
	wg.Wait()

	// 并发查询：全部应命中
	var qwg sync.WaitGroup
	for i := 0; i < n; i++ {
		qwg.Add(1)
		go func(i int) {
			defer qwg.Done()
			name := fmt.Sprintf("test-conc-%d", i)
			codec, err := EnvelopeCodecByName(name)
			assert.NoError(t, err)
			assert.Equal(t, name, codec.Name())
		}(i)
	}
	qwg.Wait()
}

// TestRegisterEnvelopeCodec_ConcurrentSameName 并发注册同名：注册表持锁且
// 永不覆盖，故恰好 1 个 goroutine 成功，其余全部 ErrEnvelopeCodecExists。
// 该测试在 -race 下运行，同时验证注册表互斥锁的并发正确性。
// 名称带纳秒时间戳后缀：注册表无删除接口，避免 -count 多次运行时名称残留。
func TestRegisterEnvelopeCodec_ConcurrentSameName(t *testing.T) {
	const n = 8
	name := fmt.Sprintf("test-race-%d", time.Now().UnixNano())
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- RegisterEnvelopeCodec(nameOnlyCodec{name: name})
		}()
	}
	wg.Wait()
	close(errs)

	success, dup := 0, 0
	for err := range errs {
		switch {
		case err == nil:
			success++
		case errors.Is(err, ErrEnvelopeCodecExists):
			dup++
		default:
			t.Fatalf("意外的注册错误: %v", err)
		}
	}
	assert.Equal(t, 1, success, "并发注册同名必须恰好 1 个成功")
	assert.Equal(t, n-1, dup, "其余注册必须返回 ErrEnvelopeCodecExists")

	// 最终注册表以首个成功者为准
	codec, err := EnvelopeCodecByName(name)
	require.NoError(t, err)
	assert.Equal(t, name, codec.Name())
}

// ==================== 内置 gcx1 适配器 ====================
// TestGCX1Codec_EquivalentToEncrypt 默认兜底回归：
// EncryptWith(EnvelopeCodecGCX1, ...) 与 Encrypt(...) 输出结构一致且可互通。
// GCM nonce 随机，字面字节必然不同，等价性以"结构一致 + 交叉可解密"验证。
func TestGCX1Codec_EquivalentToEncrypt(t *testing.T) {
	key := []byte("0123456789abcdef")
	plaintext := []byte("codec equivalence")

	envCodec, err := EncryptWith(EnvelopeCodecGCX1, rootcrypto.AES128, key, plaintext)
	require.NoError(t, err)
	envDirect, err := Encrypt(rootcrypto.AES128, key, plaintext)
	require.NoError(t, err)

	// 结构一致：均为合法 gcx1 v2 信封
	for _, env := range [][]byte{envCodec, envDirect} {
		assert.True(t, bytes.HasPrefix(env, []byte(gcx1Magic)))
		assert.Equal(t, byte(gcx1VersionV2), env[4])
		assert.Equal(t, algIDAES128, env[5])
	}

	// 交叉可解密：codec 输出可用现有 Decrypt 解开，反之亦然
	d, err := Decrypt(key, envCodec)
	require.NoError(t, err)
	assert.Equal(t, plaintext, d)
	d, err = DecryptWith(EnvelopeCodecGCX1, key, envDirect)
	require.NoError(t, err)
	assert.Equal(t, plaintext, d)

	// 带 AAD：EncryptWith(gcx1, WithAAD) 与 EncryptWithAAD 互通
	aad := []byte("context-aad")
	envCodecAAD, err := EncryptWith(EnvelopeCodecGCX1, rootcrypto.AES128, key, plaintext, rootcrypto.WithAAD(aad))
	require.NoError(t, err)
	envDirectAAD, err := EncryptWithAAD(rootcrypto.AES128, key, plaintext, aad)
	require.NoError(t, err)

	d, err = DecryptWithAAD(key, envCodecAAD, aad)
	require.NoError(t, err)
	assert.Equal(t, plaintext, d)
	d, err = DecryptWith(EnvelopeCodecGCX1, key, envDirectAAD, rootcrypto.WithAAD(aad))
	require.NoError(t, err)
	assert.Equal(t, plaintext, d)

	// 带 AAD 的密文按无 AAD 解密必须失败（AAD 语义保持）
	_, err = Decrypt(key, envCodecAAD)
	assert.Error(t, err)
}

func TestGCX1Codec_RoundTrip(t *testing.T) {
	key := []byte("0123456789abcdef")
	plaintext := []byte("gcx1 codec round trip")

	envelope, err := EncryptWith(EnvelopeCodecGCX1, rootcrypto.SM4, key, plaintext)
	require.NoError(t, err)
	decrypted, err := DecryptWith(EnvelopeCodecGCX1, key, envelope)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

// ==================== 示例适配器（应用侧自加） ====================

func TestExampleLegacyECBCodec_RoundTrip(t *testing.T) {
	codec := legacyECBCodec{}
	err := RegisterEnvelopeCodec(codec)
	require.NoError(t, err)

	key := []byte("0123456789abcdef")
	plaintext := []byte("legacy ecb payload")

	envelope, err := EncryptWith(codec.Name(), rootcrypto.AES128, key, plaintext)
	require.NoError(t, err)
	assert.NotEmpty(t, envelope)

	decrypted, err := DecryptWith(codec.Name(), key, envelope)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)

	// 错误密文拒收：非法 Base64
	_, err = DecryptWith(codec.Name(), key, []byte("!!!not-base64!!!"))
	assert.Error(t, err)

	// 错误密文拒收：Base64 合法但密文损坏（填充/对齐校验失败）
	corrupted, err := EncryptWith(codec.Name(), rootcrypto.AES128, key, plaintext)
	require.NoError(t, err)
	b, err := base64.StdEncoding.DecodeString(string(corrupted))
	require.NoError(t, err)
	b[len(b)-1] ^= 0xFF
	_, err = DecryptWith(codec.Name(), key, []byte(base64.StdEncoding.EncodeToString(b)))
	assert.Error(t, err)
}

func TestExampleCodec_ConcurrentRoundTrip(t *testing.T) {
	// 直接调用 codec 方法（不经注册表），验证无状态并发安全约定
	codec := legacyECBCodec{}
	key := []byte("0123456789abcdef")
	plaintext := []byte("concurrent legacy ecb")

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			envelope, err := codec.Encrypt(rootcrypto.AES128, key, plaintext)
			if err != nil {
				t.Errorf("Encrypt failed: %v", err)
				return
			}
			decrypted, err := codec.Decrypt(key, envelope)
			if err != nil {
				t.Errorf("Decrypt failed: %v", err)
				return
			}
			if !bytes.Equal(plaintext, decrypted) {
				t.Errorf("round trip mismatch")
			}
		}()
	}
	wg.Wait()
}

// ==================== 入口错误路径 ====================

func TestEncryptWith_UnknownCodec(t *testing.T) {
	_, err := EncryptWith("no-such-codec", rootcrypto.AES128, []byte("0123456789abcdef"), []byte("test"))
	assert.ErrorIs(t, err, ErrUnknownEnvelopeCodec)
}

func TestDecryptWith_UnknownCodec(t *testing.T) {
	_, err := DecryptWith("no-such-codec", []byte("0123456789abcdef"), []byte("test"))
	assert.ErrorIs(t, err, ErrUnknownEnvelopeCodec)
}



func TestDecryptWith_GCX1BadMagic(t *testing.T) {
	key := []byte("0123456789abcdef")
	fake := make([]byte, gcx1MinLen)
	copy(fake, gcx1Magic)
	fake[0] = 'X' // 破坏魔数

	_, errDirect := Decrypt(key, fake)
	require.Error(t, errDirect)
	_, errWith := DecryptWith(EnvelopeCodecGCX1, key, fake)
	require.Error(t, errWith)

	// 错误与现有 Decrypt 完全一致（零变化）
	assert.Equal(t, errDirect.Error(), errWith.Error())
	assert.ErrorIs(t, errWith, errGcx1MagicMismatch)
}
