package symmetric

// TestSymmetric_CFB_OFB_Concurrent CFB/OFB 模式并发加解密测试。
// 用例原位于 crypto/keymgr（阶段 5 跨包耦合清理迁入）：对称低层并发用例
// 语义上属对称子包范畴，迁入后不经注册表、直接使用本包 NewCipher，
// keymgr 侧不再依赖对称引擎的 blank import。

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSymmetric_CFB_OFB_Concurrent(t *testing.T) {
	key := make([]byte, 16)
	iv := make([]byte, 16)

	c, _ := NewCipher("AES-128", key)

	done := make(chan bool, 20)

	// CFB 并发
	for i := 0; i < 10; i++ {
		go func() {
			cfb, _ := c.NewCFB(iv)
			plaintext := []byte("concurrent CFB test data")
			encrypted, err := cfb.Encrypt(plaintext)
			assert.NoError(t, err)
			decrypted, err := cfb.Decrypt(encrypted)
			assert.NoError(t, err)
			assert.Equal(t, plaintext, []byte(decrypted))
			done <- true
		}()
	}

	// OFB 并发
	for i := 0; i < 10; i++ {
		go func() {
			ofb, _ := c.NewOFB(iv)
			plaintext := []byte("concurrent OFB test data")
			encrypted, err := ofb.Encrypt(plaintext)
			assert.NoError(t, err)
			decrypted, err := ofb.Decrypt(encrypted)
			assert.NoError(t, err)
			assert.Equal(t, plaintext, []byte(decrypted))
			done <- true
		}()
	}

	for i := 0; i < 20; i++ {
		<-done
	}
}
