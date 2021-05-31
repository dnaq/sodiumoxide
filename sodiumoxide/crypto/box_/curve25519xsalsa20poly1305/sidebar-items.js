initSidebarItems({"constant":[["MACBYTES","Number of bytes in the authenticator tag of an encrypted message i.e. the number of bytes by which the ciphertext is larger than the plaintext."],["NONCEBYTES","Number of bytes in a `Nonce`."],["PRECOMPUTEDKEYBYTES","Number of bytes in a `PrecomputedKey`."],["PUBLICKEYBYTES","Number of bytes in a `PublicKey`."],["SECRETKEYBYTES","Number of bytes in a `SecretKey`."],["SEEDBYTES","Number of bytes in a `Seed`."]],"fn":[["gen_keypair","`gen_keypair()` randomly generates a secret key and a corresponding public key."],["gen_nonce","`gen_nonce()` randomly generates a nonce"],["keypair_from_seed","`key_pair_from_seed()` deterministically derives a key pair from a single key seed (crypto_box_SEEDBYTES bytes)."],["open","`open()` verifies and decrypts a ciphertext `c` using the receiver’s secret key `sk`, the senders public key `pk`, and a nonce `n`. It returns a plaintext `Ok(m)`. If the ciphertext fails verification, `open()` returns `Err(())`."],["open_detached","`open_detached()` verifies and decrypts a ciphertext `c` using the receiver’s secret key `sk`, the senders public key `pk`, and a nonce `n`. `c` is decrypted in place, so if this function is successful it will contain the plaintext. If the ciphertext fails verification, `open_detached()` returns `Err(())`, and the ciphertext is not modified."],["open_detached_precomputed","`open_detached_precomputed()` verifies and decrypts a ciphertext `c` using a precomputed key `k` and a nonce `n`. `c` is decrypted in place, so if this function is successful it will contain the plaintext. If the ciphertext fails verification, `open_detached()` returns `Err(())`, and the ciphertext is not modified."],["open_precomputed","`open_precomputed()` verifies and decrypts a ciphertext `c` using a precomputed key `k` and a nonce `n`. It returns a plaintext `Ok(m)`. If the ciphertext fails verification, `open_precomputed()` returns `Err(())`."],["precompute","`precompute()` computes an intermediate key that can be used by `seal_precomputed()` and `open_precomputed()`"],["seal","`seal()` encrypts and authenticates a message `m` using the senders secret key `sk`, the receivers public key `pk` and a nonce `n`. It returns a ciphertext `c`."],["seal_detached","`seal_detached()` encrypts and authenticates a message `m` using the senders secret key `sk`, the receivers public key `pk` and a nonce `n`. `m` is encrypted in place, so after this function returns it will contain the ciphertext. The detached authentication tag is returned by value."],["seal_detached_precomputed","`seal_detached_precomputed()` encrypts and authenticates a message `m` using a precomputed key `k` and a nonce `n`. `m` is encrypted in place, so after this function returns it will contain the ciphertext. The detached authentication tag is returned by value."],["seal_precomputed","`seal_precomputed()` encrypts and authenticates a message `m` using a precomputed key `k`, and a nonce `n`. It returns a ciphertext `c`."]],"struct":[["Nonce","`Nonce` for asymmetric authenticated encryption"],["PrecomputedKey","Applications that send several messages to the same receiver can gain speed by splitting `seal()` into two steps, `precompute()` and `seal_precomputed()`. Similarly, applications that receive several messages from the same sender can gain speed by splitting `open()` into two steps, `precompute()` and `open_precomputed()`."],["PublicKey","`PublicKey` for asymmetric authenticated encryption"],["SecretKey","`SecretKey` for asymmetric authenticated encryption"],["Seed","`Seed` that can be used for keypair generation"],["Tag","Authentication `Tag` for the detached encryption mode"]]});