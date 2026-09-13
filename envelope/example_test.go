package envelope

// 可执行示例（P1-4）：编译进 go vet / go test 校验。
// 示例内不打印随机密文/enc——Seal 方向的 ephemeral 密钥与 nonce 每次随机，
// 打印它们会导致 Output 不确定；统一以 round-trip 成功后的固定文本作
// // Output: 断言。

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log"
)

func ExampleHPKESealWithAAD() {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	suite := HPKE_X25519_HKDF_SHA256_AES_256_GCM
	plaintext := []byte("机密 DEK")
	aad := []byte("version-key-id 绑定上下文")
	info := []byte("协议级上下文")

	enc, ciphertext, err := HPKESealWithAAD(suite, priv.PublicKey(), plaintext, aad, info)
	if err != nil {
		log.Fatal(err)
	}
	// 仅断言结构（enc 固定 32B），不打印随机密文
	fmt.Printf("enc length: %d\n", len(enc))
	fmt.Printf("ciphertext longer than plaintext: %t\n", len(ciphertext) > len(plaintext))

	// Output:
	// enc length: 32
	// ciphertext longer than plaintext: true
}

func ExampleHPKEOpenWithAAD() {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	suite := HPKE_X25519_HKDF_SHA256_AES_256_GCM
	plaintext := []byte("机密 DEK")
	aad := []byte("version-key-id 绑定上下文")
	info := []byte("协议级上下文")

	enc, ciphertext, err := HPKESealWithAAD(suite, priv.PublicKey(), plaintext, aad, info)
	if err != nil {
		log.Fatal(err)
	}

	// aad 必须与封装时逐字节一致，否则返回 ErrHPKEOpenFailed
	got, err := HPKEOpenWithAAD(suite, priv, enc, ciphertext, aad, info)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("plaintext: %s\n", got)

	_, err = HPKEOpenWithAAD(suite, priv, enc, ciphertext, []byte("篡改的 aad"), info)
	fmt.Printf("wrong aad rejected: %t\n", err == ErrHPKEOpenFailed)

	// Output:
	// plaintext: 机密 DEK
	// wrong aad rejected: true
}

func ExampleECIESSeal() {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	plaintext := []byte("机密 DEK")
	aad := []byte("上下文 AAD")

	sealed, err := ECIESSeal(&priv.PublicKey, plaintext, aad)
	if err != nil {
		log.Fatal(err)
	}
	// 输出信封总长固定为 94 + len(plaintext)，但为保持 Output 与明文长度
	// 解耦的直观性，仅断言最小长度关系（不打印随机内容）。
	fmt.Printf("sealed >= 94 + plaintext: %t\n", len(sealed) >= 94+len(plaintext))

	// Output:
	// sealed >= 94 + plaintext: true
}

func ExampleECIESOpen() {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	plaintext := []byte("机密 DEK")
	aad := []byte("上下文 AAD")

	sealed, err := ECIESSeal(&priv.PublicKey, plaintext, aad)
	if err != nil {
		log.Fatal(err)
	}

	got, err := ECIESOpen(priv, sealed, aad)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("plaintext: %s\n", got)

	// aad 不匹配 → 认证失败
	_, err = ECIESOpen(priv, sealed, []byte("错误的 AAD"))
	fmt.Printf("wrong aad rejected: %t\n", err == ErrECIESAuthFailed)

	// Output:
	// plaintext: 机密 DEK
	// wrong aad rejected: true
}
