Usage
=====

```go
package main

import (
	"fmt"
	"log"

	"github.com/nbari/crypto/scrypt"
)

func main() {
	key, err := scrypt.Create("The quick brown fox jumps over the lazy dog", 64)
	if err != nil {
		log.Fatal(err)
	}

	ok, err := scrypt.Verify("The quick brown fox jumps over the lazy dog", key)
	if err != nil {
		log.Fatal(err)
	}

    if !ok {
       log.Fatal("Could not verify...")
       return
    }

}
```


Implementation Details
----------------------

The scrypt call is invoked with these params:

    N = 16384
    r = 8
    p = 1

The salt is randomly generated from the crypto/rand library which generates a cryptographically secure pseudorandom number.

The key returned is of this format:

```pre
array index starts from left.
<---keyLen---><---16---><--4--><--4--><--4-->
   password      salt      N      r      p
```

Based on https://github.com/agnivade/easy-scrypt/ just removing the SHA-256 hash.
