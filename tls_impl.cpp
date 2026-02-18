#include "tls_impl.h"
#include "utility.h"
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/kdf.h>
#include <iostream>
#include <arpa/inet.h>
#include <memory>

using namespace std;

// ostream& operator<<(ostream& os, const vec_print& vec_print) {
//     os << vec_print.var <<" {" << vec_print.vec.size() << " bytes, hex: ";
//     for (size_t i = 0; i < vec_print.vec.size(); ++i) {
//         os << hex << setw(2) << setfill('0') << static_cast<int>(vec_print.vec[i]);
//     }
//     os << "}" << dec;
//     return os;
// }

X509* load_cert(const string& filename) {
    BIO* bio = BIO_new_file(filename.c_str(), "r");
    if (!bio) return nullptr;
    
    // PEM_read_bio_X509 converts the text-based .crt to an X509 object
    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return cert;
}

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
    // 1. Open the file
    BIO* bio = BIO_new_file(filename.c_str(), "r");
    if (!bio) {
        cerr << "Error opening private key file: " << filename << endl;
        return nullptr;
    }

    // 2. Read the private key
    // The NULLs are for password callbacks (not needed since you used -nodes)
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    
    // 3. Cleanup BIO
    BIO_free(bio);

    if (!pkey) {
        cerr << "Error reading private key from " << filename << endl;
        // You can use ERR_print_errors_fp(stderr) here for detailed OpenSSL errors
        return nullptr;
    }

    return pkey;
}

bool send_cert_chain(int fd, const vector<X509*>& certs) {
    vector<unsigned char> full_payload;
    
    for (X509* cert : certs) {
        int len = i2d_X509(cert, nullptr); // the bytes len may wiggle 1-3 bytes
        //cout << len << endl;
        if (len <= 0) return false;

        uint32_t netlen = htonl(len);
        size_t offset = full_payload.size();
        
        // Append 4-byte length + DER data
        full_payload.resize(offset + sizeof(uint32_t) + len);
        memcpy(full_payload.data() + offset, &netlen, sizeof(uint32_t));
        
        unsigned char* p = full_payload.data() + offset + sizeof(uint32_t);
        i2d_X509(cert, &p);
    }

    return send_all(fd, full_payload.data(), full_payload.size());
}

vector<X509*> recv_cert(int sock) {
    vector<X509*> ret;
    uint32_t netlen, len;
    vector<unsigned char> buf;
    const unsigned char* p;
    X509* cert = nullptr;

    if (!recv_all(sock, &netlen, sizeof(netlen))) return {};
    len = ntohl(netlen);
    if (len == 0 || len > BUF_SIZE) return {};
    //cout << len << endl;
    buf.resize(len);
    if (!recv_all(sock, buf.data(), len)) return {};
    p = buf.data();
    cert = d2i_X509(nullptr, &p, buf.size());
    if (!cert) return {};
    ret.push_back(cert);

    if (!recv_all(sock, &netlen, sizeof(netlen))) return {};
    len = ntohl(netlen);
    if (len == 0 || len > BUF_SIZE) return {};
    //cout << len << endl;
    buf.resize(len);
    if (!recv_all(sock, buf.data(), len)) return {};
    p = buf.data();
    cert = d2i_X509(nullptr, &p, buf.size());
    if (!cert) return {};
    ret.push_back(cert);

    return ret;
}

EVP_PKEY* verify_incoming(X509_STORE* global_trusted_store, vector<X509*> received_certs) {
    X509* server_cert = received_certs[0];
    X509* inter_cert = received_certs[1];
    EVP_PKEY* pubkey = nullptr;

    STACK_OF(X509)* untrusted_st = sk_X509_new_null();
    sk_X509_push(untrusted_st, inter_cert); // Push the intermediate here

    // 3. Now you can verify
    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    if (X509_STORE_CTX_init(ctx, global_trusted_store, server_cert, untrusted_st) != 1) {
        throw runtime_error("CTX init failed");
    }

    if (X509_verify_cert(ctx) != 1) {
        int err = X509_STORE_CTX_get_error(ctx);
        X509_STORE_CTX_free(ctx);
        sk_X509_free(untrusted_st);
        throw runtime_error(string("cert verify failed: ") + X509_verify_cert_error_string(err));
    }

    pubkey = X509_get_pubkey(server_cert);
    //pubkey = X509_get0_pubkey(server_cert);
    X509_STORE_CTX_free(ctx);
    sk_X509_free(untrusted_st);

    return pubkey;
}

bool send_signed_pubkey(int fd, EVP_PKEY* ephemeral_pkey, EVP_PKEY* static_priv_key) {
    int key_len = i2d_PUBKEY(ephemeral_pkey, nullptr);
    if (key_len <= 0) return false;
    vector<unsigned char> key_der(key_len);
    unsigned char* p = key_der.data();
    i2d_PUBKEY(ephemeral_pkey, &p);

    // 2. Create the Signature of the DER key
    // This proves: "I (the server) generated this specific ephemeral key"
    unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> sign_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (EVP_DigestSignInit(sign_ctx.get(), nullptr, EVP_sha256(), nullptr, static_priv_key) <= 0) return false;

    size_t sig_len = 0;
    // this sig_len is assigned with max possible length of the signature
    if (EVP_DigestSign(sign_ctx.get(), nullptr, &sig_len, key_der.data(), key_len) <= 0) return false;
    vector<unsigned char> signature(sig_len);

    // this sig_len value is changed to the real length of the signature after signing
    if (EVP_DigestSign(sign_ctx.get(), signature.data(), &sig_len, key_der.data(), key_len) <= 0) return false;

    // 3. Construct Payload: KeyLen(4) | KeyData | SigLen(4) | SigData
    uint32_t net_key_len = htonl(key_len);
    uint32_t net_sig_len = htonl(sig_len);

    vector<unsigned char> payload;
    payload.insert(payload.end(), (unsigned char*)&net_key_len, (unsigned char*)&net_key_len + 4);
    payload.insert(payload.end(), key_der.begin(), key_der.begin() + key_len);
    payload.insert(payload.end(), (unsigned char*)&net_sig_len, (unsigned char*)&net_sig_len + 4);
    payload.insert(payload.end(), signature.begin(), signature.begin() + sig_len);

    cout << "[Server] Sending signed ephemeral key. Total payload: " << payload.size() << " bytes." << endl;
    return send_all(fd, payload.data(), payload.size());
}

EVP_PKEY* recv_and_verify_signed_key(int sock, EVP_PKEY* server_static_pub)
{
    uint32_t net_len = 0;
    uint32_t key_len = 0;

    // ---- 1. Read key length ----
    if (!recv_all(sock, &net_len, sizeof(net_len)))
        throw runtime_error("recv key len fail");

    key_len = ntohl(net_len);
    //cout << key_len << endl;
    if (key_len == 0 || key_len > BUF_SIZE)
        throw runtime_error("invalid key len");

    // ---- 2. Read key DER ----
    vector<unsigned char> key_der(key_len);
    if (!recv_all(sock, key_der.data(), key_len))
        throw runtime_error("recv key der fail");

    // ---- 3. Read signature length ----
    if (!recv_all(sock, &net_len, sizeof(net_len)))
        throw runtime_error("recv sig len fail");

    uint32_t sig_len = ntohl(net_len);
    //cout << sig_len << endl;
    if (sig_len == 0 || sig_len > BUF_SIZE)
        throw runtime_error("invalid sig len");

    // ---- 4. Read signature ----
    vector<unsigned char> signature(sig_len);
    if (!recv_all(sock, signature.data(), sig_len))
        throw runtime_error("recv signature fail");

    // ---- 5. Verify signature ----
    auto ctx = unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>(
        EVP_MD_CTX_new(), EVP_MD_CTX_free);

    if (!ctx)
        throw runtime_error("md ctx alloc fail");

    if (EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha256(),
                             nullptr, server_static_pub) <= 0)
        throw runtime_error("verify init fail");

    int ok = EVP_DigestVerify(ctx.get(),
                              signature.data(), sig_len,
                              key_der.data(), key_len);

    if (ok != 1) throw runtime_error("signature verification failed");

    // ---- 6. Decode DER to EVP_PKEY ----
    const unsigned char* p = key_der.data();
    EVP_PKEY* ephemeral_pub = d2i_PUBKEY(nullptr, &p, key_len);
    if (!ephemeral_pub)
        throw runtime_error("d2i_PUBKEY fail");

    cout << "[Client] Verified signed ephemeral key." << endl;

    return ephemeral_pub; // caller owns
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

vector<unsigned char> derive_shared_secret(EVP_PKEY* priv_key, EVP_PKEY* peer_pubkey) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv_key, nullptr); // context now know priv_key is Elliptic Curve
    vector<unsigned char> secret;
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
vector<unsigned char> hkdf_extract_and_expand(
    const vector<unsigned char>& salt,
    const vector<unsigned char>& input_key_material,
    const string& info,
    size_t length
) {
    unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> pctx_ptr(
        EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr), 
        EVP_PKEY_CTX_free
    );
    EVP_PKEY_CTX* pctx = pctx_ptr.get();
    vector<unsigned char> out_key(length);

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

    // PRK = HMAC-SHA256(salt, input_key_material)
    // out_key(32 bytes) = HMAC-SHA256(PRK, info + 0x01)
    if (EVP_PKEY_derive(pctx, out_key.data(), &length) <= 0)
        throw runtime_error("EVP_PKEY_derive failed");

    return out_key;
}

// Construct per-record IV: base_iv XOR seq_num
vector<unsigned char> make_record_iv(const vector<unsigned char>& base_iv, uint64_t seq_num) {
    vector<unsigned char> iv(base_iv);
    // XOR seq_num into the last 8 bytes (4-11 bytes, network byte order)
    for (int i = 0; i < 8; i++) {
        iv[GCM_IV_LEN - 1 - i] ^= (seq_num >> (8 * i)) & 0xFF;
    }
    return iv;
}

bool aes_gcm_encrypt_send(
    int sock,
    string& plaintext,
    vector<unsigned char>& key,     // 32 bytes
    vector<unsigned char>& base_iv, // 12 bytes
    uint64_t& seq
) {
    unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx_ptr(
        EVP_CIPHER_CTX_new(), 
        EVP_CIPHER_CTX_free
    );
    EVP_CIPHER_CTX* ctx = ctx_ptr.get();
    vector<unsigned char> iv, ciphertext, tag, record;
    int outlen = 0, ciphertext_len = 0;
    uint32_t payload_len;
    unsigned char header[5];

    iv = make_record_iv(base_iv, seq);

    if (!ctx) { return false; }
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) { return false; }
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key.data(), iv.data()) != 1) { return false; }

    // step 1: stream = AES_Key(IV + Counter), AES_Key is 32 bytes, Counter + 1 per 16 bytes of plaintext
    // step 2: ciphertext = plaintext ^ stream, same bytes length for ciphertext and plaintext
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

    payload_len = (uint32_t)(ciphertext.size() + tag.size());
    if (payload_len > 0xFFFF) return false; // TLS record length limit

    header[0] = TLS_APPLICATION_DATA;
    header[1] = (unsigned char)((TLS_VERSION >> 8) & 0xff);
    header[2] = (unsigned char)(TLS_VERSION & 0xff);
    header[3] = (unsigned char)((payload_len >> 8) & 0xff);
    header[4] = (unsigned char)(payload_len & 0xff);

    record.insert(record.end(), header, header + sizeof(header));
    record.insert(record.end(), ciphertext.begin(), ciphertext.end());
    record.insert(record.end(), tag.begin(), tag.end());
    seq++;
    return send_all(sock, record.data(), record.size());
}

bool aes_gcm_recv_decrypt(
    int sock,
    string& recv_msg,
    vector<unsigned char>& key,     // 32 bytes
    vector<unsigned char>& base_iv, // 12 bytes
    uint64_t& seq
) {
    uint8_t content_type;
    uint16_t version, payload_len;
    unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx_ptr(
        EVP_CIPHER_CTX_new(), 
        EVP_CIPHER_CTX_free
    );
    EVP_CIPHER_CTX* ctx = ctx_ptr.get();
    vector<unsigned char> payload, iv, ciphertext, tag, out;
    int outlen = 0;
    unsigned char header[5];

    iv = make_record_iv(base_iv, seq);

    if (!ctx) { throw runtime_error("EVP_CIPHER_CTX_new fail"); return false;}
    if (!recv_all(sock, header, sizeof(header))) { throw runtime_error("header received fail"); return false;}

#ifdef DEBUG
    printf("[DEBUG] Received Header: %02x %02x %02x %02x %02x\n", 
        header[0], header[1], header[2], header[3], header[4]);
#endif
    
    content_type = header[0];
    version = (header[1] << 8) | header[2];
    payload_len = (header[3] << 8) | header[4];
    if (content_type != TLS_APPLICATION_DATA) { throw runtime_error("content_type not match"); return false;}
    if (version != TLS_VERSION) { throw runtime_error("version not match"); return false;}
    if (payload_len < GCM_TAG_LEN) { throw runtime_error("payload_len not match"); return false;}
    payload.resize(payload_len);
    if (!recv_all(sock, payload.data(), payload_len)) { throw runtime_error("payload received fail"); return false;}

    // Split into ciphertext | tag
    ciphertext.assign(payload.begin(), payload.end() - GCM_TAG_LEN);
    tag.assign(payload.end() - GCM_TAG_LEN, payload.end());

    out.resize(ciphertext.size());

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) { throw runtime_error("EVP_DecryptInit_ex failed"); return false; }
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), iv.data()) != 1) { throw runtime_error("EVP_DecryptInit_ex failed"); return false; }
    if (EVP_DecryptUpdate(ctx, out.data(), &outlen, ciphertext.data(), ciphertext.size()) != 1) { throw runtime_error("EVP_DecryptUpdate failed"); return false; }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), (void*)tag.data()) != 1) { throw runtime_error("EVP_CIPHER_CTX_ctrl failed"); return false; }
    if (EVP_DecryptFinal_ex(ctx, out.data() + outlen, &outlen) != 1) { throw runtime_error("EVP_DecryptFinal_ex failed"); return false; }

    recv_msg.assign(out.begin(), out.end());
    seq++;
    return true;
}
