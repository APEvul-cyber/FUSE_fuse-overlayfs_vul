# ovl_create: umask strip leaves S_ISUID

`mode & ~umask` still allows 04711. Upper file can be setuid-root.

Please strip setuid/setgid bits.