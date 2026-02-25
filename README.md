# TLS-Handshake-Implementation
* This project simulates X.509 certificate and TLS handshake using ECDHE key exchange and encrypt using AES-GCM afterward. We use also use secure vault to store the secret so the space is zero out when leaving the scope.

<h2> Testing Environment </h2>

* Testing on ubuntu with wsl
  ```sh
  ~/TLS-Handshake-Implementation$ lsb_release -a
  No LSB modules are available.
  Distributor ID: Ubuntu
  Description:    Ubuntu 24.04.2 LTS
  Release:        24.04
  Codename:       noble
  ```

<h2> How to build</h2>

* install OpenSSL library (install tcpdump optionally as well)
  ```sh
  apt install libssl-dev
  apt  install tcpdump
  ```
* compile server
  ```sh
  g++ tls_server.cpp tls_impl.cpp -lssl -lcrypto -o tls_server
  ```
* compile client
  ```sh
  g++ tls_client.cpp tls_impl.cpp -lssl -lcrypto -o tls_client
  ```

<h2> Testing </h2>

* open a command prompt running server
  ```sh
  ./tls_server
  ```

* open another command prompt running client
  ```sh
  ./tls_client
  ```
* the result printing on the command prompt
  ```sh
  ~/TLS-Handshake-Implementation$ ./tls_server
  Certificate request self-signature ok
  subject=CN = MyIntermediateCA
  Certificate request self-signature ok
  subject=CN = localhost
  [Server] listening on port 5555
  [Server] client connected
  [Server] Sending certificates and signed ephemeral key. Total payload: 1009 bytes.
  [Server] client says: READY
  [Server] server sends: OK
  [Server] server sends: something interesting but only you can know
  [Server] client says: Got it.
  ```
  ```sh
  ~/TLS-Handshake-Implementation$ ./tls_client
  [Client] connected to server
  send pub key: 95 bytes.
  [Client] Verified signed ephemeral server public key.
  [Client] client sends: READY
  [Client] server says: OK
  [Client] server says: something interesting but only you can know
  [Client] client sends: Got it.
  ```

<h2> Logic Flow </h2>

* Certificate request and approve both sides using ECDSA:

  Certificate request contains 3 blocks:
  ```sh
  1. The Metadata (Name, Domain, Public Key).
  2. The Algorithm ID (e.g., ecdsa-with-SHA256).
  3. The Signature (r, s).
  ```

  requester or certificate signer:
  ```sh
  r = k * G (mod n)
  s = (k^-1)(SHA-256(Metadata) + r * PrivateKey) (mod n)
  # k is random number, G, n are picked by EC Algorithm
  ```

  verify side:
  ```sh
  u_1 = SHA-256(Metadata) * (s^-1) (mod n)
  u_2 = r * (s^-1) (mod n)
  P = (u_1 * G) + (u_2 * PublicKey) (mod n)
  Check if the x-coordinate of P matches r
  ```

* Both sides agree on using NID_X9_62_prime256v1:

  ```sh
  Elliptic Curve is y^2 = x^3 - 3x + b (mod p)
  b is a large constant, p = 2^256 - 2^224 + 2^192 + 2^96 - 1 is a 256 bits prime
  Q = d * G
  Q = (x, y), d is private key, G is a base point on the curve
  # public key is 65 bytes: 0x04(Uncompressed) + x(32 bytes) + y(32 bytes), private key is d (32 bytes)
  ```

* Derive the same secrets using ECDHE:
  ```sh
  server:
  A = a * G (mod p), a is server private epheneral key, A is server public epheneral key
  client:
  B = b * G (mod p), b is server private epheneral key, B is server public epheneral key
  share secret on both side (if attacker only knows A, B, G, Secret is almost impossible to compute):
  Secret = a * b * G = a * B = b * A (mod p)
  ```

* Using HKDF (secure duo combo with ECDHE) to calculate client derived key, client iv, server derived key, server iv:
  ```sh
    HMAC-SHA256(K, m) = SHA256([K XOR opad][SHA256(K XOR ipad)][m])    
    PRK = HMAC-SHA256(salt, IKM)
    OKM(32 bytes) = HMAC-SHA256(PRK, info + 0x01)

    # K: the salt or PRK, m: the input_key_material or info
    # IKM: Input Key Material, PRK: Pseudorandom Key, OKM: Output Key Material
  ```

* For generating a deterministic initialization vector (IV), the following formula is applied to compute separately for each direction of messages to prevent replay attack:
  ```sh
  IV = base_iv XOR (0x00000000 || sequence_number), 12 bytes
  sequence_number += 1 when send or receive on the corresponding direction
  ```

* AES-GCM:
  ```sh
  step 1: stream(16 bytes) = AES_256_Encrypt(AES_Key, [IV(96 bits)][Counter(32 bits)]), AES_Key is 32 bytes, Counter + 1 per 16 bytes of plaintext. Noted that Counter is per packet and it will be reset to 1 and sequence_number will +1 for the next packet.
  step 2: ciphertext = plaintext ^ stream, repeat for the next 16 bytes data
  step 3: tag = GHASH(H, AAD, ciphertext) XOR AES_256_Encrypt(AES_Key, [IV(96 bits)][0x00000001(32 bits)]), tag is 16 bytes, H = AES_256_Encrypt(AES_Key, 0x000...0)
  ```

<h2> Security Notes</h2>
This project is not production ready, it is still weak to:

* Side channel. For example: 
  
  ```sh
  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) { throw runtime_error("EVP_DecryptInit_ex failed"); return false; }
  if (EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), iv.data()) != 1) { throw runtime_error("EVP_DecryptInit_ex failed"); return false; }
  if (EVP_DecryptUpdate(ctx, out.data(), &outlen, ciphertext.data(), ciphertext.size()) != 1) { throw runtime_error("EVP_DecryptUpdate failed"); return false; }
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), (void*)tag.data()) != 1) { throw runtime_error("EVP_CIPHER_CTX_ctrl failed"); return false; }
  if (EVP_DecryptFinal_ex(ctx, out.data() + outlen, &outlen) != 1) { throw runtime_error("EVP_DecryptFinal_ex failed"); return false; }
  ```

  1. Accumulate a "Failure Bit": Instead of throwing immediately, use a variable: int status = 1;.

  2. Bitwise Updates:
  
  ```sh
  status &= EVP_DecryptUpdate(...);
  status &= EVP_DecryptFinal_ex(...);
  ```

  3. Unified Throw: Only check the status at the very end of the function, and ensure the time taken to reach that check is identical regardless of which step failed.

  4. Dummy Work: If EVP_DecryptUpdate fails early, we should still "pretend" to do the rest of the work (or wait a calibrated amount of time) so the attacker always sees the same latency.

* It should have new ephemeral keys when sequence number reaching 2^20 (repeat iv is dangerous because ciphertext got cancel out using XOR)

* Disable core dump to ensure secret is not dumped

* And more...
