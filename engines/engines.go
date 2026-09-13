// Package engines provides a convenient blank import to register all official
// cryptographic engines provided by the crypto package.
//
// # Usage
//
// Import this package with a blank identifier to register all engines:
//
//	import (
//	    crypto "github.com/charlienet/go-crypto"
//	    _ "github.com/charlienet/go-crypto/engines"
//	)
//
// This is equivalent to importing each engine individually:
//
//	import (
//	    _ "github.com/charlienet/go-crypto/symmetric"
//	    _ "github.com/charlienet/go-crypto/asym"
//	    _ "github.com/charlienet/go-crypto/agreement"
//	    _ "github.com/charlienet/go-crypto/keymgr"
//	)
//
// For fine-grained control over which engines are registered, import them
// individually. This is useful when you want to minimize binary size or
// restrict available algorithms for security policy reasons.
package engines

import (
	_ "github.com/charlienet/go-crypto/agreement"
	_ "github.com/charlienet/go-crypto/asym"
	_ "github.com/charlienet/go-crypto/keymgr"
	_ "github.com/charlienet/go-crypto/symmetric"
)
