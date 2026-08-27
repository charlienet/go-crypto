package hmac

import (
	"encoding/hex"
	"testing"
)

func TestHmac(t *testing.T) {
	key, _ := hex.DecodeString("98123F7FDEB5255E18B9446A2C161024")

	c := `POST
x-ca-key:25080476
x-ca-nonce:r3dz9x3f
x-ca-timestamp:1754373030
/api/authcode/generate
{"card":"jkfsdklafkjdsgf","channel":"70","phone":"18483657766","timeout":"60s","version":"V1"}`

	s, _ := New("HMACSM3", []byte(c))
	sign, _ := s.Sign(key)

	t.Log(sign.Base64())

}
