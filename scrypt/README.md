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
<---password---><---16---><--4--><--4--><--4--><----32---->
      dkey         salt      N      r      p   sha-256 hash
```

A SHA-256 of the entire content(dKey+salt+n+r+p) is computed and stored at the end to just verify the integrity of the content.

Based on: https://github.com/agnivade/easy-scrypt/
