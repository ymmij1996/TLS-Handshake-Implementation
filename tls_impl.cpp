#include "tls_impl.h"
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/kdf.h>
#include <iostream>
#include <arpa/inet.h>
#include <memory>

using namespace std;

X509* load_cert(const string& filename) {
    BIO* bio = BIO_new_file(filename.c_str(), "r");
    if (!bio) return nullptr;
    
    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return cert;
}


// ---------------------------------------
// openssl req -in server.csr -noout -text
//
// Certificate Request:
// Data:
//     Version: 1 (0x0)
//     Subject: CN = localhost
//     Subject Public Key Info:
//         Public Key Algorithm: id-ecPublicKey
//             Public-Key: (256 bit)
//             pub:
//                 04:dc:f1:2e:04:d0:24:0f:d6:f1:13:fb:67:f1:4d:
//                 48:43:7f:74:98:38:44:7d:6e:25:67:9f:73:20:d5:
//                 25:87:7e:f3:92:bf:ee:13:16:b9:2f:14:aa:9e:dc:
//                 8d:bb:1c:18:ee:35:7d:f0:7d:7e:6f:14:45:81:4f:
//                 32:66:d7:58:d6
//             ASN1 OID: prime256v1
//             NIST CURVE: P-256
//     Attributes:
//         (none)
//         Requested Extensions:
// Signature Algorithm: ecdsa-with-SHA256
// Signature Value:
//     30:46:02:21:00:a4:23:08:11:dc:b7:34:b9:c4:6b:ec:6a:82:
//     29:69:c4:04:3f:31:a7:cf:e0:fe:09:90:0a:5d:35:0c:01:54:
//     55:02:21:00:95:97:eb:3b:e9:a5:64:9e:01:16:62:e0:6e:c8:
//     cc:e3:1d:d8:cf:86:e5:23:3a:ba:e4:a3:60:a4:01:b6:5a:61

// Block A: The Metadata (Name, Domain, Public Key).
// Block B: The Algorithm ID (e.g., ecdsa-with-SHA256).
// Block C: The Signature (r, s).

// requester:
// r = k * G (mod n)
// s = (k^-1)(SHA-256(Metadata) + r * PrivateKey) (mod n)
// k is random number, G, n are picked by EC Algorithm

// CA verify:
// u_1 = SHA-256(Metadata) * (s^-1) (mod n)
// u_2 = r * (s^-1) (mod n)
// P = (u_1 * G) + (u_2 * PublicKey) (mod n)
// Check if the x-coordinate of P matches r

// ---------------------------------------
// openssl x509 -in root.crt -text -noout
//
// Certificate:
//     Data:
//         Version: 3 (0x2)
//         Serial Number:
//             42:48:db:74:63:81:4e:e3:b8:e8:72:fc:c1:53:d0:73:97:8a:15:55
//         Signature Algorithm: ecdsa-with-SHA256
//         Issuer: CN = MyRootCA
//         Validity
//             Not Before: Feb 18 02:58:14 2026 GMT
//             Not After : Feb 16 02:58:14 2036 GMT
//         Subject: CN = MyRootCA
//         Subject Public Key Info:
//             Public Key Algorithm: id-ecPublicKey
//                 Public-Key: (256 bit)
//                 pub:
//                     04:78:f0:a3:47:a4:a4:bd:5e:35:ce:b8:61:81:78:
//                     c6:9f:65:4e:e7:31:89:70:3a:39:28:6c:96:1e:7f:
//                     ca:ff:9f:eb:a2:61:7e:ae:96:0c:b0:4f:e5:72:f8:
//                     44:75:f7:3c:8a:30:48:5d:2e:d5:22:7b:e5:f9:62:
//                     b3:dd:45:e1:a2
//                 ASN1 OID: prime256v1
//                 NIST CURVE: P-256
//         X509v3 extensions:
//             X509v3 Subject Key Identifier:
//                 CC:48:47:BF:B2:56:FE:F4:50:4C:57:1E:47:B2:D9:36:2A:D4:97:2D
//             X509v3 Authority Key Identifier:
//                 CC:48:47:BF:B2:56:FE:F4:50:4C:57:1E:47:B2:D9:36:2A:D4:97:2D
//             X509v3 Basic Constraints: critical
//                 CA:TRUE
//     Signature Algorithm: ecdsa-with-SHA256
//     Signature Value:
//         30:45:02:20:5c:ff:f6:4d:87:67:4b:cb:ce:ee:74:28:09:cf:
//         4d:a8:75:ca:4b:c9:aa:93:08:74:97:68:57:8d:ef:09:ac:d6:
//         02:21:00:ac:23:7d:51:4b:ae:4e:f3:2f:0f:95:c2:bc:4b:fc:
//         59:57:02:9f:9d:24:36:6e:7c:4b:fe:14:aa:ad:58:15:62

// TBS = NewMetadata, r, s, k are all new values from CA, PrivateKey and PublicKey are CA's
// n, G depend on CA's algorithm decision

// CA sign:
// r = k * G (mod n)
// s = (k^-1)(SHA-256(TBS) + r * PrivateKey) (mod n)
// k is random number, G, n are picked by EC Algorithm

// User(Browser) verify:
// u_1 = SHA-256(TBS) * (s^-1) (mod n)
// u_2 = r * (s^-1) (mod n)
// P = (u_1 * G) + (u_2 * PublicKey) (mod n)

void simulate_x509() {
    system("echo \"\nbasicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n\" > ca_ext.cnf");
    system("echo \"\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nsubjectAltName=DNS:localhost\n\" > server_ext.cnf");

    system("openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out root.key");

    system("openssl req -x509 -new -key root.key -sha256 -days 3650 "
           "-out root.crt -subj \"/CN=MyRootCA\" "
           "-extensions v3_ca "
           "-config /etc/ssl/openssl.cnf");

    system("openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out intermediate.key");

    system("openssl req -new -key intermediate.key -out intermediate.csr "
           "-subj \"/CN=MyIntermediateCA\"");

    system("openssl x509 -req -in intermediate.csr -CA root.crt -CAkey root.key "
           "-CAcreateserial -out intermediate.crt -days 3650 -sha256 "
           "-extfile ca_ext.cnf");

    system("openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out server.key");
    
    system("openssl req -new -key server.key -out server.csr "
           "-subj \"/CN=localhost\"");

    system("openssl x509 -req -in server.csr -CA intermediate.crt -CAkey intermediate.key "
           "-CAcreateserial -out server.crt -days 365 -sha256 "
           "-extfile server_ext.cnf");
}


EVP_PKEY* load_private_key(const string& filename) {
    BIO* bio = BIO_new_file(filename.c_str(), "r");
    if (!bio) {
        cerr << "Error opening private key file: " << filename << endl;
        return nullptr;
    }

    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    
    BIO_free(bio);

    if (!pkey) {
        cerr << "Error reading private key from " << filename << endl;
        // ERR_print_errors_fp(stderr)
        return nullptr;
    }

    return pkey;
}

EVP_PKEY* recv_pubkey(int fd) {
    uint32_t netlen;
    if (!recv_all(fd, &netlen, sizeof(netlen))) return nullptr;
    uint32_t len = ntohl(netlen);
    if (len == 0 || len > BUF_SIZE) return nullptr;
    vector<unsigned char> buf(len);
    if (!recv_all(fd, buf.data(), len)) return nullptr;
    const unsigned char* p = buf.data();
    return d2i_PUBKEY(nullptr, &p, len);
}

// pkt format: [Len][Cert1][Len][Cert2][Len][EphemeralPubKey][Len][Sig]
bool send_cert_chain_signed_pubkey(int fd, const vector<X509*>& certs, EVP_PKEY* ephemeral_key, EVP_PKEY* static_priv_key) {
    int key_len = i2d_PUBKEY(ephemeral_key, nullptr);
    if (key_len <= 0) return false;

    unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> sign_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    vector<int> cert_len(certs.size());
    vector<unsigned char> ephemeral_key_der(key_len), signature, payload;
    uint32_t net_key_len, net_sig_len, payload_len = 0;
    size_t sig_len = 0;
    unsigned char* p;
    int i = 0, offset = 0;
    
    for (X509* cert : certs) {
        int len = i2d_X509(cert, nullptr); // the bytes len may wiggle 1-3 bytes
        if (len <= 0) return false;
        cert_len[i] = len;
        payload_len = payload_len + 4 + len;
        ++i;
    }

    p = ephemeral_key_der.data();
    i2d_PUBKEY(ephemeral_key, &p);

    // ECDSA: server sign ephemeral server key using server static private key
    if (EVP_DigestSignInit(sign_ctx.get(), nullptr, EVP_sha256(), nullptr, static_priv_key) <= 0) return false;

    // this sig_len is assigned with max possible length of the signature
    if (EVP_DigestSign(sign_ctx.get(), nullptr, &sig_len, ephemeral_key_der.data(), key_len) <= 0) return false;
    signature.resize(sig_len);

    // this sig_len value is changed to the real length of the signature after signing
    if (EVP_DigestSign(sign_ctx.get(), signature.data(), &sig_len, ephemeral_key_der.data(), key_len) <= 0) return false;

    payload_len = payload_len + key_len + sig_len + 8;
    payload.resize(payload_len);

    i = 0;
    for (X509* cert : certs) {
        uint32_t netlen = htonl(cert_len[i]);
        
        // Append 4-byte length + DER data
        memcpy(payload.data() + offset, &netlen, 4);
        offset += 4;
        p = payload.data() + offset;
        i2d_X509(cert, &p);
        offset += cert_len[i];
        ++i;
    }

    // KeyLen(4) | KeyData | SigLen(4) | SigData
    net_key_len = htonl(key_len);
    net_sig_len = htonl(sig_len);

    
    memcpy(payload.data() + offset, &net_key_len, 4);
    offset += 4;
    memcpy(payload.data() + offset, ephemeral_key_der.data(), key_len);
    offset += key_len;
    memcpy(payload.data() + offset, &net_sig_len, 4);
    offset += 4;
    memcpy(payload.data() + offset, signature.data(), sig_len);

    cout << "[Server] Sending certificates and signed ephemeral key. Total payload: " << payload.size() << " bytes." << endl;
    return send_all(fd, payload.data(), payload.size());
}

EVP_PKEY* recv_verify_cert(int sock, X509_STORE* global_trusted_store) {
    uint32_t netlen, len;
    vector<unsigned char> buf;
    const unsigned char* p;
    X509 *server_cert, *inter_cert;
    EVP_PKEY* pubkey = nullptr;
    STACK_OF(X509)* untrusted_st = sk_X509_new_null();
    unique_ptr<X509_STORE_CTX, decltype(&X509_STORE_CTX_free)> ctx_ptr(
        X509_STORE_CTX_new(), 
        X509_STORE_CTX_free
    );

    if (!recv_all(sock, &netlen, sizeof(netlen))) return {};
    len = ntohl(netlen);
    if (len == 0 || len > BUF_SIZE) return {};
    buf.resize(len);
    if (!recv_all(sock, buf.data(), len)) return {};
    p = buf.data();
    server_cert = d2i_X509(nullptr, &p, buf.size());
    if (!server_cert) return {};

    if (!recv_all(sock, &netlen, sizeof(netlen))) return {};
    len = ntohl(netlen);
    if (len == 0 || len > BUF_SIZE) return {};
    buf.resize(len);
    if (!recv_all(sock, buf.data(), len)) return {};
    p = buf.data();
    inter_cert = d2i_X509(nullptr, &p, buf.size());
    if (!inter_cert) return {};

    sk_X509_push(untrusted_st, inter_cert); // Push the intermediate here
    
    if (!ctx_ptr || X509_STORE_CTX_init(ctx_ptr.get(), global_trusted_store, server_cert, untrusted_st) != 1) {
        throw runtime_error("CTX init failed");
    }

    // this verify all cert: root CA cert (client local installed), inter CA cert and server cert (get from server)
    if (X509_verify_cert(ctx_ptr.get()) != 1) {
        int err = X509_STORE_CTX_get_error(ctx_ptr.get());
        sk_X509_free(untrusted_st);
        throw runtime_error(string("cert verify failed: ") + X509_verify_cert_error_string(err));
    }

    pubkey = X509_get_pubkey(server_cert);
    //pubkey = X509_get0_pubkey(server_cert);
    sk_X509_free(untrusted_st);

    return pubkey;
}

EVP_PKEY* recv_and_verify_signed_key(int sock, EVP_PKEY* server_static_pub)
{
    uint32_t net_len = 0, key_len = 0, sig_len;
    vector<unsigned char> key_der, signature;
    unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    const unsigned char* p;
    EVP_PKEY* ephemeral_server_pub;

    if (!recv_all(sock, &net_len, sizeof(net_len)))
        throw runtime_error("recv key len fail");

    key_len = ntohl(net_len);
    if (key_len == 0 || key_len > BUF_SIZE)
        throw runtime_error("invalid key len");

    key_der.resize(key_len); // ephemeral server public key
    if (!recv_all(sock, key_der.data(), key_len))
        throw runtime_error("recv key der fail");

    if (!recv_all(sock, &net_len, sizeof(net_len)))
        throw runtime_error("recv sig len fail");

    sig_len = ntohl(net_len);
    if (sig_len == 0 || sig_len > BUF_SIZE)
        throw runtime_error("invalid sig len");

    signature.resize(sig_len);
    if (!recv_all(sock, signature.data(), sig_len))
        throw runtime_error("recv signature fail");

    // ECDSA: verify server ephemeral public key using server static public key
    if (!ctx || EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha256(), nullptr, server_static_pub) <= 0) {
        throw runtime_error("verify init fail");
    }

    if (EVP_DigestVerify(ctx.get(), signature.data(), sig_len, key_der.data(), key_len) != 1) {
        throw runtime_error("signature verification failed");
    }

    p = key_der.data();
    ephemeral_server_pub = d2i_PUBKEY(nullptr, &p, key_len);
    if (!ephemeral_server_pub) throw runtime_error("d2i_PUBKEY ephemeral_server_pub fail");

    cout << "[Client] Verified signed ephemeral server public key." << endl;
    return ephemeral_server_pub; // caller owns
}


EVP_PKEY* generate_ec_key() {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    EVP_PKEY* pkey = nullptr;
    if (!pctx) return nullptr;
    if (EVP_PKEY_keygen_init(pctx) != 1) { EVP_PKEY_CTX_free(pctx); return nullptr; }

    // NID_X9_62_prime256v1:
    // curve is y^2 = x^3 - 3x + b (mod p)
    // b is a large constant, p = 2^256 - 2^224 + 2^192 + 2^96 - 1 is a prime
    // Q = d * G
    // Q = (x, y), d is private key, G is a base point on the curve
    // public key is 65 bytes: 0x04(Uncompressed) + x(32 bytes) + y(32 bytes), private key is d (32 bytes)
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1);
    EVP_PKEY_keygen(pctx, &pkey);

    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

bool send_pubkey(int fd, EVP_PKEY* pkey) {
    // 4 bytes | DER(65 bytes) ~ 91 bytes
    // key len | DER(public key)
    int len = i2d_PUBKEY(pkey, nullptr); // i2d d stands for DER-encoded
    if (len <= 0) return false;
    uint32_t netlen = htonl(len);

    vector<unsigned char> buf(sizeof(int) + len); // the first 4 bytes store the length
    memcpy(buf.data(), &netlen, sizeof(int)); // copy netlen
    unsigned char* p = buf.data() + sizeof(int);
    i2d_PUBKEY(pkey, &p);
    cout << "send pub key: " << buf.size() << " bytes." << endl;
    return send_all(fd, buf.data(), buf.size());
}

SecureVector derive_shared_secret(EVP_PKEY* priv_key, EVP_PKEY* peer_pubkey) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv_key, nullptr); // context now know priv_key is Elliptic Curve
    SecureVector secret;
    size_t secret_len = 0;

    if (!ctx) return {};
    if (EVP_PKEY_derive_init(ctx) != 1) { EVP_PKEY_CTX_free(ctx); return {}; }
    if (EVP_PKEY_derive_set_peer(ctx, peer_pubkey) != 1) { EVP_PKEY_CTX_free(ctx); return {}; }
    
    EVP_PKEY_derive(ctx, nullptr, &secret_len); // check curve type -> 32 bytes
    secret.resize(secret_len);

    // S = d * Q , only pick x in S as secret
    if (EVP_PKEY_derive(ctx, secret.data(), &secret_len) <= 0) { // check peer_pubkey and priv_key are on the same curve
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        cout << "EVP_PKEY_derive failed: " <<  err_buf << endl;
        EVP_PKEY_CTX_free(ctx);
        return {};
    }
    secret.resize(secret_len);
    EVP_PKEY_CTX_free(ctx);
    return secret;
}

// salt: vector of salt bytes (can be all zeros for first use)
// input_key_material: shared_secret from ECDHE
// info: make sure client and server have different iv when use this to hash
// length: desired output key length in bytes
SecureVector hkdf_extract_and_expand(
    const SecureVector& salt,
    const SecureVector& input_key_material,
    const string& info,
    size_t length
) {
    unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> pctx_ptr(
        EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr), 
        EVP_PKEY_CTX_free
    );
    EVP_PKEY_CTX* pctx = pctx_ptr.get();
    SecureVector out_key(length);

    // just filling pctx
    if (!pctx)
        throw runtime_error("EVP_PKEY_CTX_new_id failed");

    if (EVP_PKEY_derive_init(pctx) <= 0)
        throw runtime_error("EVP_PKEY_derive_init failed");

    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0)
        throw runtime_error("EVP_PKEY_CTX_set_hkdf_md failed");

    // these set1 and add1 functions usually succeed unless OOM
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.data(), salt.size()) <= 0)
        throw runtime_error("EVP_PKEY_CTX_set1_hkdf_salt failed");

    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, input_key_material.data(), input_key_material.size()) <= 0)
        throw runtime_error("EVP_PKEY_CTX_set1_hkdf_key failed");

    if (!info.empty()) {
        if (EVP_PKEY_CTX_add1_hkdf_info(pctx,
                reinterpret_cast<const unsigned char*>(info.data()),
                info.size()) <= 0)
            throw runtime_error("EVP_PKEY_CTX_add1_hkdf_info failed");
    }

    // HMAC(K, m) = SHA256((K XOR opad) || SHA256((K XOR ipad) || m))    
    // PRK = HMAC-SHA256(salt, IKM)
    // OKM(32 bytes) = HMAC-SHA256(PRK, info + 0x01)

    // K: the salt or PRK, m: the input_key_material or info, ||: Concatenation.
    // IKM: Input Key Material, PRK: Pseudorandom Key, OKM: Output Key Material
    if (EVP_PKEY_derive(pctx, out_key.data(), &length) <= 0)
        throw runtime_error("EVP_PKEY_derive failed");

    return out_key;
}

// Construct per-record IV: base_iv XOR seq_num
SecureVector make_record_iv(const SecureVector& base_iv, uint64_t seq_num) {
    SecureVector iv(base_iv);
    // XOR seq_num into the last 8 bytes (4-11 bytes, network byte order)
    for (int i = 0; i < 8; i++) {
        iv[GCM_IV_LEN - 1 - i] ^= (seq_num >> (8 * i)) & 0xFF;
    }
    return iv;
}

bool aes_gcm_encrypt_send(
    int sock,
    string& plaintext,
    SecureVector& key,     // 32 bytes
    SecureVector& base_iv, // 12 bytes
    uint64_t& seq
) {
    unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx_ptr(
        EVP_CIPHER_CTX_new(), 
        EVP_CIPHER_CTX_free
    );
    EVP_CIPHER_CTX* ctx = ctx_ptr.get();
    SecureVector iv, ciphertext, tag;
    vector<unsigned char> record;
    int outlen = 0, ciphertext_len = 0;
    uint32_t payload_len;
    unsigned char header[5];
    uint64_t be_seq = htobe64(seq); // Ensure big-endian for network consistency

    iv = make_record_iv(base_iv, seq);

    payload_len = (uint32_t)(plaintext.size() + GCM_TAG_LEN);
    if (payload_len > 0xFFFF) return false;

    header[0] = TLS_APPLICATION_DATA;
    header[1] = (unsigned char)((TLS_VERSION >> 8) & 0xff);
    header[2] = (unsigned char)(TLS_VERSION & 0xff);
    header[3] = (unsigned char)((payload_len >> 8) & 0xff);
    header[4] = (unsigned char)(payload_len & 0xff);

    if (!ctx) { return false; }
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) { return false; }
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key.data(), iv.data()) != 1) { return false; }

    // FEED AAD (Sequence Number + Header)
    if (EVP_EncryptUpdate(ctx, NULL, &outlen, (unsigned char*)&be_seq, sizeof(be_seq)) != 1) return false;
    if (EVP_EncryptUpdate(ctx, NULL, &outlen, header, sizeof(header)) != 1) return false;

    // step 1: stream(16 bytes) = AES_256_Encrypt(AES_Key, [IV(96 bits)][Counter(32 bits)]), AES_Key is 32 bytes, Counter + 1 per 16 bytes of plaintext
    // step 2: ciphertext = plaintext ^ stream, repeat for next 16 bytes
    ciphertext.resize(plaintext.size());
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &outlen, (const unsigned char*)plaintext.data(), plaintext.size()) != 1) { return false; }
    ciphertext_len = outlen;

    // this write 0 bytes to ciphertext
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + outlen, &outlen) != 1) { return false; }
    ciphertext_len += outlen;
    ciphertext.resize(ciphertext_len); // redundant but safe

    // step 3: tag = GHASH(ciphertext), tag is 16 bytes
    tag.resize(GCM_TAG_LEN);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1) { return false; }

    record.insert(record.end(), header, header + sizeof(header));
    record.insert(record.end(), ciphertext.begin(), ciphertext.end());
    record.insert(record.end(), tag.begin(), tag.end());
    seq++;
    return send_all(sock, record.data(), record.size());
}

bool aes_gcm_recv_decrypt(
    int sock,
    string& recv_msg,
    SecureVector& key,     // 32 bytes
    SecureVector& base_iv, // 12 bytes
    uint64_t& seq
) {
    bool success = true;
    uint8_t content_type;
    uint16_t version, payload_len;
    unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx_ptr(
        EVP_CIPHER_CTX_new(), 
        EVP_CIPHER_CTX_free
    );
    EVP_CIPHER_CTX* ctx = ctx_ptr.get();
    SecureVector payload, iv, ciphertext, tag, out;
    int outlen = 0, aad_outlen;
    unsigned char header[5];
    uint64_t be_seq = htobe64(seq);

    iv = make_record_iv(base_iv, seq);
    if (!recv_all(sock, header, sizeof(header))) {
        return false;
    }
    if (!ctx) { throw runtime_error("EVP_CIPHER_CTX_new fail"); return false;}

#ifdef DEBUG
    printf("[DEBUG] Received Header: %02x %02x %02x %02x %02x\n", 
        header[0], header[1], header[2], header[3], header[4]);
#endif
    
    content_type = header[0];
    version = (header[1] << 8) | header[2];
    payload_len = (header[3] << 8) | header[4];
    if (content_type != TLS_APPLICATION_DATA || version != TLS_VERSION || payload_len < GCM_TAG_LEN) {
        throw runtime_error("verify header fail");
        return false;
    }
    
    payload.resize(payload_len);
    if (!recv_all(sock, payload.data(), payload_len)) { throw runtime_error("payload received fail"); return false;}

    // Split into ciphertext | tag
    ciphertext.assign(payload.begin(), payload.end() - GCM_TAG_LEN);
    tag.assign(payload.end() - GCM_TAG_LEN, payload.end());

    out.resize(ciphertext.size());

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) { throw runtime_error("EVP_DecryptInit_ex failed"); return false; }
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), iv.data()) != 1) { throw runtime_error("EVP_DecryptInit_ex failed"); return false; }
    if (EVP_DecryptUpdate(ctx, NULL, &aad_outlen, (unsigned char*)&be_seq, sizeof(be_seq)) != 1) { throw runtime_error("EVP_DecryptUpdate failed"); return false; }
    if (EVP_DecryptUpdate(ctx, NULL, &aad_outlen, header, sizeof(header)) != 1) { throw runtime_error("EVP_DecryptUpdate failed"); return false; }
    if (EVP_DecryptUpdate(ctx, out.data(), &outlen, ciphertext.data(), ciphertext.size()) != 1) { throw runtime_error("EVP_DecryptUpdate failed"); return false; }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), (void*)tag.data()) != 1) { throw runtime_error("EVP_CIPHER_CTX_ctrl failed"); return false; }
    if (EVP_DecryptFinal_ex(ctx, out.data() + outlen, &outlen) != 1) { throw runtime_error("EVP_DecryptFinal_ex failed"); return false; }

    recv_msg.assign(out.begin(), out.end());
    seq++;
    return true;
}
