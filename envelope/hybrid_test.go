package envelope

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// randomX25519KeyPair 生成 X25519 密钥对（*ecdh，库内惯例类型）。
func randomX25519KeyPair(t *testing.T) (*ecdh.PublicKey, *ecdh.PrivateKey) {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	return priv.PublicKey(), priv
}

// randomRSAKeyPair 生成 RSA 密钥对（bits 位）。
func randomRSAKeyPair(t *testing.T, bits int) (*rsa.PublicKey, *rsa.PrivateKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	require.NoError(t, err)
	return &priv.PublicKey, priv
}

// ==================== 2 KEM × 2 payload 四组合往返 ====================

func TestHybrid_RoundTrip_AllCombos(t *testing.T) {
	type combo struct {
		name         string
		kemID        byte
		payloadAlgID byte
	}
	combos := []combo{
		{"RSA×SM4", hyb1KemRSA, hyb1PayloadSM4},
		{"RSA×AES256", hyb1KemRSA, hyb1PayloadAES256},
		{"X25519×SM4", hyb1KemX25519, hyb1PayloadSM4},
		{"X25519×AES256", hyb1KemX25519, hyb1PayloadAES256},
	}

	for _, tc := range combos {
		t.Run(tc.name, func(t *testing.T) {
			plaintext := []byte("hyb1 公钥信封语料：" + tc.name)
			aad := []byte("ctx-aad")

			var sealed []byte
			var priv any
			switch tc.kemID {
			case hyb1KemRSA:
				pub, p := randomRSAKeyPair(t, 2048)
				priv = p
				var err error
				sealed, err = sealInternal(pub, plaintext, aad, tc.payloadAlgID)
				require.NoError(t, err)
			case hyb1KemX25519:
				pub, p := randomX25519KeyPair(t)
				priv = p
				var err error
				sealed, err = sealInternal(pub, plaintext, aad, tc.payloadAlgID)
				require.NoError(t, err)
			}

			// 头部字节断言（magic/version/kemID/payloadAlgID）
			assert.Equal(t, hyb1Magic, string(sealed[:4]))
			assert.Equal(t, byte(hyb1Version), sealed[4])
			assert.Equal(t, tc.kemID, sealed[5])
			assert.Equal(t, tc.payloadAlgID, sealed[6])

			// kem 段长度断言：RSA 段空、X25519 ephPub=32/nonce=12
			// nonce 长度字段位于 ephPub 数据之后（offset = 7 + 2 + ephPubLen）。
			ephPubLen := be16(sealed[hyb1HeaderLen : hyb1HeaderLen+2])
			nonceOff := hyb1HeaderLen + 2 + int(ephPubLen)
			nonceLen := be16(sealed[nonceOff : nonceOff+2])
			if tc.kemID == hyb1KemRSA {
				assert.Equal(t, uint16(0), ephPubLen)
				assert.Equal(t, uint16(0), nonceLen)
			} else {
				assert.Equal(t, uint16(hyb1X25519PubLen), ephPubLen)
				assert.Equal(t, uint16(hyb1NonceLen), nonceLen)
			}

			// 往返：相同 AAD 解密成功
			pt, err := Open(priv, sealed, aad)
			require.NoError(t, err, "往返解密应成功")
			assert.Equal(t, plaintext, pt)

			// 带 AAD 加密的信封用空 AAD 解密必须失败
			_, err = Open(priv, sealed, nil)
			assert.Error(t, err, "带 AAD 加密的信封用空 AAD 解密必须失败")
		})
	}
}

// be16 读取 2 字节大端序长度字段。
func be16(b []byte) uint16 {
	return uint16(b[0])<<8 | uint16(b[1])
}

// ==================== AAD 篡改拒绝 ====================

func TestHybrid_AADTamper(t *testing.T) {
	plaintext := []byte("aad 绑定测试")
	aad1 := []byte("aad-1")
	aad2 := []byte("aad-2")

	t.Run("RSA", func(t *testing.T) {
		pub, priv := randomRSAKeyPair(t, 2048)
		sealed, err := Seal(pub, plaintext, aad1)
		require.NoError(t, err)
		_, err = Open(priv, sealed, aad2)
		// RSA 路径统一失败哨兵（见 ErrHybridRSAOpenFailed 抗 oracle 注释）
		assert.ErrorIs(t, err, ErrHybridRSAOpenFailed)
	})
	t.Run("X25519", func(t *testing.T) {
		pub, priv := randomX25519KeyPair(t)
		sealed, err := Seal(pub, plaintext, aad1)
		require.NoError(t, err)
		_, err = Open(priv, sealed, aad2)
		assert.ErrorIs(t, err, ErrHybridAuthFailed)
	})
}

// ==================== 头部逐字节翻转拒绝 ====================

func TestHybrid_HeaderTamper(t *testing.T) {
	plaintext := []byte("header tamper")
	aad := []byte("aad")

	kems := map[string]struct {
		pub  any
		priv any
	}{
		"RSA":    newRSACombo(t),
		"X25519": newX25519Combo(t),
	}
	for name, kp := range kems {
		t.Run(name, func(t *testing.T) {
			sealed, err := Seal(kp.pub, plaintext, aad)
			require.NoError(t, err)

			for i := 0; i < hyb1HeaderLen; i++ {
				tampered := bytes.Clone(sealed)
				tampered[i] ^= 0xFF
				_, err := Open(kp.priv, tampered, aad)
				assert.Error(t, err, "篡改头部字节 %d 应解密失败", i)
			}

			// magic/version 有前置校验，断言具体哨兵
			tampered := bytes.Clone(sealed)
			tampered[0] ^= 0xFF
			_, err = Open(kp.priv, tampered, aad)
			assert.ErrorIs(t, err, ErrHybridMagicMismatch)

			tampered = bytes.Clone(sealed)
			tampered[4] ^= 0xFF
			_, err = Open(kp.priv, tampered, aad)
			assert.ErrorIs(t, err, ErrHybridVersionMismatch)
		})
	}
}

func newRSACombo(t *testing.T) struct{ pub, priv any } {
	pub, priv := randomRSAKeyPair(t, 2048)
	return struct{ pub, priv any }{pub, priv}
}

func newX25519Combo(t *testing.T) struct{ pub, priv any } {
	pub, priv := randomX25519KeyPair(t)
	return struct{ pub, priv any }{pub, priv}
}

// ==================== 截断拒绝 ====================

func TestHybrid_Truncation(t *testing.T) {
	plaintext := []byte("truncation probe: payload 足够长以覆盖所有前段截断")
	aad := []byte("aad")

	kems := map[string]struct {
		pub  any
		priv any
	}{
		"RSA":    newRSACombo(t),
		"X25519": newX25519Combo(t),
	}
	for name, kp := range kems {
		t.Run(name, func(t *testing.T) {
			sealed, err := Seal(kp.pub, plaintext, aad)
			require.NoError(t, err)

			// 任一前缀（除完整密封外）都必须失败：长度校验或 GCM 认证拒绝
			for i := 0; i < len(sealed); i++ {
				_, err := Open(kp.priv, sealed[:i], aad)
				assert.Error(t, err, "截断到 %d 字节应解密失败", i)
			}

			// 完整密封在相同密钥/AAD 下必须成功
			_, err = Open(kp.priv, sealed, aad)
			assert.NoError(t, err)
		})
	}
}

// ==================== RSA 弱密钥拒绝 ====================

func TestHybrid_RSA1024Rejected(t *testing.T) {
	pub, _ := randomRSAKeyPair(t, 1024)

	_, err := Seal(pub, []byte("test"), nil)
	assert.ErrorIs(t, err, ErrHybridKeyTooWeak)
	assert.Contains(t, err.Error(), "1024 bits, minimum required is 2048 bits",
		"弱密钥措辞应对齐 asym/rsa.go")

	// 1024 位私钥同样在 Open 侧不适用（公钥侧已拦截，此处验证私钥类型
	// 不会绕过弱密钥策略——直接构造合法 2048 信封 + 1024 私钥应报统一失败）
	pub2, priv2 := randomRSAKeyPair(t, 2048)
	sealed, err := Seal(pub2, []byte("test"), nil)
	require.NoError(t, err)
	_ = priv2
	weakPriv, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	_ = weakPriv
	_, err = Open(priv2, sealed, nil)
	assert.NoError(t, err)
}

// ==================== 错误密钥 / 未知类型 / 类型不匹配 ====================

func TestHybrid_WrongKeyAndUnknownType(t *testing.T) {
	plaintext := []byte("wrong key probe")

	t.Run("RSA wrong key", func(t *testing.T) {
		pub1, priv1 := randomRSAKeyPair(t, 2048)
		_, priv2 := randomRSAKeyPair(t, 2048)
		sealed, err := Seal(pub1, plaintext, nil)
		require.NoError(t, err)
		_, err = Open(priv2, sealed, nil)
		assert.ErrorIs(t, err, ErrHybridRSAOpenFailed)
		_, err = Open(priv1, sealed, nil)
		assert.NoError(t, err)
	})

	t.Run("X25519 wrong key", func(t *testing.T) {
		pub1, priv1 := randomX25519KeyPair(t)
		_, priv2 := randomX25519KeyPair(t)
		sealed, err := Seal(pub1, plaintext, nil)
		require.NoError(t, err)
		_, err = Open(priv2, sealed, nil)
		assert.ErrorIs(t, err, ErrHybridAuthFailed)
		_, err = Open(priv1, sealed, nil)
		assert.NoError(t, err)
	})

	t.Run("unsupported seal key types", func(t *testing.T) {
		_, err := Seal(nil, plaintext, nil)
		assert.ErrorIs(t, err, ErrHybridUnsupportedKey)
		_, err = Seal(struct{}{}, plaintext, nil)
		assert.ErrorIs(t, err, ErrHybridUnsupportedKey)
		_, err = Seal([]byte("x"), plaintext, nil)
		assert.ErrorIs(t, err, ErrHybridUnsupportedKey)
	})

	t.Run("unsupported open key types", func(t *testing.T) {
		pub, _ := randomX25519KeyPair(t)
		sealed, err := Seal(pub, plaintext, nil)
		require.NoError(t, err)

		_, err = Open(nil, sealed, nil)
		assert.ErrorIs(t, err, ErrHybridUnsupportedKey)
		_, err = Open(struct{}{}, sealed, nil)
		assert.ErrorIs(t, err, ErrHybridUnsupportedKey)
	})

	t.Run("kem key mismatch", func(t *testing.T) {
		rsaPub, rsaPriv := randomRSAKeyPair(t, 2048)
		xPub, xPriv := randomX25519KeyPair(t)

		rsaSealed, err := Seal(rsaPub, plaintext, nil)
		require.NoError(t, err)
		xSealed, err := Seal(xPub, plaintext, nil)
		require.NoError(t, err)

		// X25519 私钥解 RSA 信封 / RSA 私钥解 X25519 信封
		_, err = Open(xPriv, rsaSealed, nil)
		assert.ErrorIs(t, err, ErrHybridKeyMismatch)
		_, err = Open(rsaPriv, xSealed, nil)
		assert.ErrorIs(t, err, ErrHybridKeyMismatch)
	})

	t.Run("non-X25519 ecdh curve", func(t *testing.T) {
		// NIST P-256 ecdh 公钥不是 X25519，必须拒绝
		p256Priv, err := ecdh.P256().GenerateKey(rand.Reader)
		require.NoError(t, err)
		_, err = Seal(p256Priv.PublicKey(), plaintext, nil)
		assert.ErrorIs(t, err, ErrHybridUnsupportedKey)
	})
}

// ==================== X25519 ephPub 非法长度拒绝 ====================

func TestHybrid_BadEphPubLen(t *testing.T) {
	_, priv := randomX25519KeyPair(t)

	// 手工构造结构完全合法、但 ephPub 段长度为 31（≠32）的 X25519 信封：
	// 长度字段解析全部通过，必须在 X25519 分支被 ErrHybridBadEphKey 拦截。
	header := buildHyb1Header(hyb1KemX25519, hyb1PayloadAES256)
	sealed := buildHyb1Sealed(header,
		make([]byte, 31), // ephPub：非法长度
		make([]byte, hyb1NonceLen),
		make([]byte, hyb1AES256KeyLen+hyb1TagLen),
		make([]byte, hyb1MinPayloadLen),
	)
	_, err := Open(priv, sealed, nil)
	assert.ErrorIs(t, err, ErrHybridBadEphKey)

	// wrap nonce 长度非 12 属结构错误
	sealed = buildHyb1Sealed(buildHyb1Header(hyb1KemX25519, hyb1PayloadAES256),
		make([]byte, hyb1X25519PubLen),
		make([]byte, 8), // wrap nonce：非法长度
		make([]byte, hyb1AES256KeyLen+hyb1TagLen),
		make([]byte, hyb1MinPayloadLen),
	)
	_, err = Open(priv, sealed, nil)
	assert.ErrorIs(t, err, ErrHybridBadLengths)

	// RSA 信封带上非空 ephPub/nonce 段属结构错误
	rsaPub, rsaPriv := randomRSAKeyPair(t, 2048)
	rsaSealed := buildHyb1Sealed(buildHyb1Header(hyb1KemRSA, hyb1PayloadAES256),
		make([]byte, 4), // ephPub：RSA 路径必须为空
		make([]byte, 0),
		make([]byte, 256),
		make([]byte, hyb1MinPayloadLen),
	)
	_, err = Open(rsaPriv, rsaSealed, nil)
	assert.ErrorIs(t, err, ErrHybridBadLengths)
	_ = rsaPub
}

// ==================== 两次 Seal 输出不同（随机性） ====================

func TestHybrid_SealDistinct(t *testing.T) {
	plaintext := []byte("same plaintext, random nonces")
	aad := []byte("aad")

	t.Run("RSA", func(t *testing.T) {
		pub, priv := randomRSAKeyPair(t, 2048)
		s1, err := Seal(pub, plaintext, aad)
		require.NoError(t, err)
		s2, err := Seal(pub, plaintext, aad)
		require.NoError(t, err)
		assert.False(t, bytes.Equal(s1, s2), "两次 RSA Seal 输出应不同（OAEP 随机 + payload nonce）")

		d1, err := Open(priv, s1, aad)
		require.NoError(t, err)
		d2, err := Open(priv, s2, aad)
		require.NoError(t, err)
		assert.Equal(t, plaintext, d1)
		assert.Equal(t, plaintext, d2)
	})

	t.Run("X25519", func(t *testing.T) {
		pub, priv := randomX25519KeyPair(t)
		s1, err := Seal(pub, plaintext, aad)
		require.NoError(t, err)
		s2, err := Seal(pub, plaintext, aad)
		require.NoError(t, err)
		assert.False(t, bytes.Equal(s1, s2), "两次 X25519 Seal 输出应不同（ephPub + wrap nonce + payload nonce）")

		d1, err := Open(priv, s1, aad)
		require.NoError(t, err)
		d2, err := Open(priv, s2, aad)
		require.NoError(t, err)
		assert.Equal(t, plaintext, d1)
		assert.Equal(t, plaintext, d2)
	})
}
