package envelope

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestECIESRoundTrip(t *testing.T) {
	// 生成 P-256 密钥对
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	tests := []struct {
		name      string
		plaintext []byte
		aad       []byte
	}{
		{"empty plaintext", []byte{}, nil},
		{"empty plaintext with aad", []byte{}, []byte("aad")},
		{"small plaintext", []byte("hello world"), nil},
		{"small plaintext with aad", []byte("hello world"), []byte("context")},
		{"medium plaintext", make([]byte, 1024), nil},
		{"medium plaintext with aad", make([]byte, 1024), []byte("authenticated data")},
		{"large plaintext", make([]byte, 64*1024), []byte("large data")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Seal
			sealed, err := ECIESSeal(&priv.PublicKey, tt.plaintext, tt.aad)
			if err != nil {
				t.Fatalf("ECIESSeal: %v", err)
			}

			// Open
			plaintext, err := ECIESOpen(priv, sealed, tt.aad)
			if err != nil {
				t.Fatalf("ECIESOpen: %v", err)
			}

			// 验证明文一致
			if string(plaintext) != string(tt.plaintext) {
				t.Errorf("plaintext mismatch: got %q, want %q", plaintext, tt.plaintext)
			}
		})
	}
}

func TestECIESAAD(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	plaintext := []byte("test data")
	aad := []byte("authenticated data")

	// 使用 AAD 加密
	sealed, err := ECIESSeal(&priv.PublicKey, plaintext, aad)
	if err != nil {
		t.Fatalf("ECIESSeal: %v", err)
	}

	t.Run("correct aad", func(t *testing.T) {
		// 相同 AAD 解密成功
		dec, err := ECIESOpen(priv, sealed, aad)
		if err != nil {
			t.Errorf("ECIESOpen with correct aad: %v", err)
		}
		if string(dec) != string(plaintext) {
			t.Errorf("plaintext mismatch with correct aad")
		}
	})

	t.Run("wrong aad", func(t *testing.T) {
		// 不同 AAD 解密失败
		_, err := ECIESOpen(priv, sealed, []byte("wrong aad"))
		if err == nil {
			t.Error("ECIESOpen with wrong aad should fail")
		}
		if err != ErrECIESAuthFailed {
			t.Errorf("wrong error: got %v, want ErrECIESAuthFailed", err)
		}
	})

	t.Run("nil vs empty aad", func(t *testing.T) {
		// nil AAD 与空 AAD 应等价
		sealedNil, err := ECIESSeal(&priv.PublicKey, plaintext, nil)
		if err != nil {
			t.Fatalf("ECIESSeal with nil aad: %v", err)
		}

		sealedEmpty, err := ECIESSeal(&priv.PublicKey, plaintext, []byte{})
		if err != nil {
			t.Fatalf("ECIESSeal with empty aad: %v", err)
		}

		// 使用 nil AAD 加密的信封用 nil AAD 解密
		dec, err := ECIESOpen(priv, sealedNil, nil)
		if err != nil {
			t.Errorf("ECIESOpen sealedNil with nil aad: %v", err)
		}
		if string(dec) != string(plaintext) {
			t.Errorf("plaintext mismatch with nil aad")
		}

		// 使用空 AAD 加密的信封用空 AAD 解密
		dec, err = ECIESOpen(priv, sealedEmpty, []byte{})
		if err != nil {
			t.Errorf("ECIESOpen sealedEmpty with empty aad: %v", err)
		}
		if string(dec) != string(plaintext) {
			t.Errorf("plaintext mismatch with empty aad")
		}
	})
}

func TestECIESErrors(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	t.Run("invalid curve", func(t *testing.T) {
		// 使用 P-384 密钥应返回 ErrECIESInvalidCurve
		priv384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey P-384: %v", err)
		}

		_, err = ECIESSeal(&priv384.PublicKey, []byte("test"), nil)
		if err != ErrECIESInvalidCurve {
			t.Errorf("P-384 seal: got %v, want ErrECIESInvalidCurve", err)
		}

		// 先用 P-256 加密，再用 P-384 私钥解密
		sealed, err := ECIESSeal(&priv.PublicKey, []byte("test"), nil)
		if err != nil {
			t.Fatalf("ECIESSeal P-256: %v", err)
		}
		_, err = ECIESOpen(priv384, sealed, nil)
		if err != ErrECIESInvalidCurve {
			t.Errorf("P-384 open: got %v, want ErrECIESInvalidCurve", err)
		}
	})

	t.Run("truncated input", func(t *testing.T) {
		sealed, err := ECIESSeal(&priv.PublicKey, []byte("test"), nil)
		if err != nil {
			t.Fatalf("ECIESSeal: %v", err)
		}

		// 截断信封（密文部分被截断，GCM 会检测到认证失败）
		truncated := sealed[:len(sealed)-1]
		_, err = ECIESOpen(priv, truncated, nil)
		if err != ErrECIESAuthFailed {
			t.Errorf("truncated ciphertext: got %v, want ErrECIESAuthFailed", err)
		}

		// 截断头部（nonce 部分）
		headerTruncated := sealed[:70] // 只有 ephPubLen + ephPub + 部分 nonce
		_, err = ECIESOpen(priv, headerTruncated, nil)
		if err != ErrECIESTooShort {
			t.Errorf("header truncated: got %v, want ErrECIESTooShort", err)
		}

		// 过短的信封
		_, err = ECIESOpen(priv, []byte{0x41}, nil)
		if err != ErrECIESTooShort {
			t.Errorf("very short seal: got %v, want ErrECIESTooShort", err)
		}
	})

	t.Run("tampered ciphertext", func(t *testing.T) {
		sealed, err := ECIESSeal(&priv.PublicKey, []byte("test"), nil)
		if err != nil {
			t.Fatalf("ECIESSeal: %v", err)
		}

		// 篡改密文（偏移 78 之后是 ciphertext）
		tampered := make([]byte, len(sealed))
		copy(tampered, sealed)
		tampered[80] ^= 0xFF

		_, err = ECIESOpen(priv, tampered, nil)
		if err != ErrECIESAuthFailed {
			t.Errorf("tampered ciphertext: got %v, want ErrECIESAuthFailed", err)
		}
	})

	t.Run("tampered ephPub", func(t *testing.T) {
		sealed, err := ECIESSeal(&priv.PublicKey, []byte("test"), nil)
		if err != nil {
			t.Fatalf("ECIESSeal: %v", err)
		}

		// 篡改临时公钥（偏移 1-65）
		tampered := make([]byte, len(sealed))
		copy(tampered, sealed)
		tampered[10] ^= 0xFF

		_, err = ECIESOpen(priv, tampered, nil)
		// 篡改公钥可能导致无效点或认证失败
		if err != ErrECIESInvalidEphPub && err != ErrECIESAuthFailed {
			t.Errorf("tampered ephPub: got %v, want ErrECIESInvalidEphPub or ErrECIESAuthFailed", err)
		}
	})

	t.Run("invalid ephPubLen", func(t *testing.T) {
		sealed, err := ECIESSeal(&priv.PublicKey, []byte("test"), nil)
		if err != nil {
			t.Fatalf("ECIESSeal: %v", err)
		}

		// 修改 ephPubLen 字段
		tampered := make([]byte, len(sealed))
		copy(tampered, sealed)
		tampered[0] = 0x20 // 不是 0x41

		_, err = ECIESOpen(priv, tampered, nil)
		if err != ErrECIESTooShort {
			t.Errorf("invalid ephPubLen: got %v, want ErrECIESTooShort", err)
		}
	})

	t.Run("nil key", func(t *testing.T) {
		_, err := ECIESSeal(nil, []byte("test"), nil)
		if err != ErrECIESInvalidCurve {
			t.Errorf("nil public key: got %v, want ErrECIESInvalidCurve", err)
		}

		_, err = ECIESOpen(nil, []byte("test"), nil)
		if err != ErrECIESInvalidCurve {
			t.Errorf("nil private key: got %v, want ErrECIESInvalidCurve", err)
		}
	})
}

func TestECIESEmptyPlaintext(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	// 空明文加密
	sealed, err := ECIESSeal(&priv.PublicKey, []byte{}, nil)
	if err != nil {
		t.Fatalf("ECIESSeal empty: %v", err)
	}

	// 解密
	plaintext, err := ECIESOpen(priv, sealed, nil)
	if err != nil {
		t.Fatalf("ECIESOpen empty: %v", err)
	}

	if len(plaintext) != 0 {
		t.Errorf("empty plaintext mismatch: got %d bytes, want 0", len(plaintext))
	}
}

func TestECIESConcurrency(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	// 并发加密解密测试（验证并发安全）
	const goroutines = 10
	const iterations = 100

	done := make(chan bool, goroutines)

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			for j := 0; j < iterations; j++ {
				plaintext := []byte("concurrent test data")
				aad := []byte("aad")

				sealed, err := ECIESSeal(&priv.PublicKey, plaintext, aad)
				if err != nil {
					t.Errorf("goroutine %d: ECIESSeal: %v", id, err)
					return
				}

				dec, err := ECIESOpen(priv, sealed, aad)
				if err != nil {
					t.Errorf("goroutine %d: ECIESOpen: %v", id, err)
					return
				}

				if string(dec) != string(plaintext) {
					t.Errorf("goroutine %d: plaintext mismatch", id)
					return
				}
			}
			done <- true
		}(i)
	}

	for i := 0; i < goroutines; i++ {
		<-done
	}
}

func BenchmarkECIESSeal(b *testing.B) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	plaintext := make([]byte, 32)
	aad := []byte("benchmark-aad")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := ECIESSeal(&priv.PublicKey, plaintext, aad)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkECIESOpen(b *testing.B) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	plaintext := make([]byte, 32)
	aad := []byte("benchmark-aad")
	sealed, _ := ECIESSeal(&priv.PublicKey, plaintext, aad)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := ECIESOpen(priv, sealed, aad)
		if err != nil {
			b.Fatal(err)
		}
	}
}