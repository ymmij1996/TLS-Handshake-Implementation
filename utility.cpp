#include "utility.h"
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/kdf.h>
#include <iostream>
#include <arpa/inet.h>

using namespace std;

// --- pubkey send/recv (DER) ---
// --- pubkey send/recv ---
bool send_pubkey(int fd, EVP_PKEY* pkey) {
    int len = i2d_PUBKEY(pkey, nullptr);
    if (len <= 0) return false;
    uint32_t netlen = htonl(len);

    vector<unsigned char> buf(sizeof(int) + len); // the first 4 bytes store the length
    memcpy(buf.data(), &netlen, sizeof(int)); // copy netlen
    unsigned char* p = buf.data() + sizeof(int);
    i2d_PUBKEY(pkey, &p);
    return send_all(fd, buf.data(), buf.size());
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
// --- crypto helpers ---
EVP_PKEY* generate_ec_key() {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    EVP_PKEY* pkey = nullptr;
    if (!pctx) return nullptr;
    if (EVP_PKEY_keygen_init(pctx) != 1) { EVP_PKEY_CTX_free(pctx); return nullptr; }
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1);
    EVP_PKEY_keygen(pctx, &pkey);
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}
vector<unsigned char> derive_shared_secret(EVP_PKEY* priv_key, EVP_PKEY* peer_pubkey) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv_key, nullptr);
    vector<unsigned char> secret;
    if (!ctx) return secret;
    if (EVP_PKEY_derive_init(ctx) != 1) { EVP_PKEY_CTX_free(ctx); return secret; }
    if (EVP_PKEY_derive_set_peer(ctx, peer_pubkey) != 1) { EVP_PKEY_CTX_free(ctx); return secret; }
    size_t secret_len = 0;
    EVP_PKEY_derive(ctx, nullptr, &secret_len);
    secret.resize(secret_len);
    EVP_PKEY_derive(ctx, secret.data(), &secret_len);
    EVP_PKEY_CTX_free(ctx);
    secret.resize(secret_len);
    return secret;
}
vector<unsigned char> sha256(const vector<unsigned char>& in) {
    vector<unsigned char> out(SHA256_DIGEST_LENGTH);
    SHA256(in.data(), in.size(), out.data());
    return out;
}

// salt: vector of salt bytes (can be all zeros for first use)
// input_key_material: shared_secret from ECDHE
// info: optional context string (e.g., "TLS handshake key")
// length: desired output key length in bytes
vector<unsigned char> hkdf_extract_and_expand(
    const vector<unsigned char>& salt,
    const vector<unsigned char>& input_key_material,
    const string& info,
    size_t length
) {
    EVP_PKEY_CTX *pctx;
    vector<unsigned char> out_key(length);

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!pctx)
        throw std::runtime_error("EVP_PKEY_CTX_new_id failed");

    if (EVP_PKEY_derive_init(pctx) <= 0)
        throw std::runtime_error("EVP_PKEY_derive_init failed");

    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0)
        throw std::runtime_error("EVP_PKEY_CTX_set_hkdf_md failed");

    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.data(), salt.size()) <= 0)
        throw std::runtime_error("EVP_PKEY_CTX_set1_hkdf_salt failed");

    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, input_key_material.data(), input_key_material.size()) <= 0)
        throw std::runtime_error("EVP_PKEY_CTX_set1_hkdf_key failed");

    if (!info.empty()) {
        if (EVP_PKEY_CTX_add1_hkdf_info(pctx,
                reinterpret_cast<const unsigned char*>(info.data()),
                info.size()) <= 0)
            throw std::runtime_error("EVP_PKEY_CTX_add1_hkdf_info failed");
    }

    if (EVP_PKEY_derive(pctx, out_key.data(), &length) <= 0)
        throw std::runtime_error("EVP_PKEY_derive failed");

    EVP_PKEY_CTX_free(pctx);
    return out_key;
}

// --- socket utils ---
bool send_all(int fd, const void* data, size_t len) {
    const unsigned char* p = (const unsigned char*)data;
    while (len > 0) {
        ssize_t s = send(fd, p, len, 0);
        if (s <= 0) return false;
        p += s; len -= s;
    }
    return true;
}
bool recv_all(int fd, void* data, size_t len) {
    unsigned char* p = (unsigned char*)data;
    while (len > 0) {
        ssize_t r = recv(fd, p, len, 0);
        if (r <= 0) return false;
        p += r; len -= r;
    }
    return true;
}

bool aes_gcm_encrypt(const vector<unsigned char>& key,
                     const string& plaintext,
                     vector<unsigned char>& ciphertext,
                     vector<unsigned char>& iv,
                     vector<unsigned char>& tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    iv.resize(GCM_IV_LEN);
    if (RAND_bytes(iv.data(), iv.size()) != 1) { EVP_CIPHER_CTX_free(ctx); return false; }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) { EVP_CIPHER_CTX_free(ctx); return false; }
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key.data(), iv.data()) != 1) { EVP_CIPHER_CTX_free(ctx); return false; }

    ciphertext.resize(plaintext.size());
    int outlen = 0;
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &outlen, (const unsigned char*)plaintext.data(), plaintext.size()) != 1) { EVP_CIPHER_CTX_free(ctx); return false; }
    int ciphertext_len = outlen;
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + outlen, &outlen) != 1) { EVP_CIPHER_CTX_free(ctx); return false; }
    ciphertext_len += outlen;
    ciphertext.resize(ciphertext_len);

    tag.resize(GCM_TAG_LEN);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1) { EVP_CIPHER_CTX_free(ctx); return false; }
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool aes_gcm_decrypt(const vector<unsigned char>& key,
                     const vector<unsigned char>& ciphertext,
                     const vector<unsigned char>& iv,
                     const vector<unsigned char>& tag,
                     string& plaintext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) { EVP_CIPHER_CTX_free(ctx); return false; }
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), iv.data()) != 1) { EVP_CIPHER_CTX_free(ctx); return false; }

    vector<unsigned char> out(ciphertext.size());
    int outlen = 0;
    if (EVP_DecryptUpdate(ctx, out.data(), &outlen, ciphertext.data(), ciphertext.size()) != 1) { EVP_CIPHER_CTX_free(ctx); return false; }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), (void*)tag.data()) != 1) { EVP_CIPHER_CTX_free(ctx); return false; }

    int ret = EVP_DecryptFinal_ex(ctx, out.data() + outlen, &outlen);
    EVP_CIPHER_CTX_free(ctx);
    if (ret <= 0) return false;
    plaintext.assign(out.begin(), out.end());
    return true;
}

// --- GCM packet send/recv ---
bool send_gcm_packet(int fd,
                     const vector<unsigned char>& iv,
                     const vector<unsigned char>& tag,
                     const vector<unsigned char>& ciphertext) {
    uint32_t payload_len = (uint32_t)(iv.size() + ciphertext.size() + tag.size());
    if (payload_len > 0xFFFF) return false; // TLS record length limit

    const unsigned char header[5] = {
        TLS_APPLICATION_DATA,
        (unsigned char)((TLS_VERSION >> 8) & 0xff),
        (unsigned char)(TLS_VERSION & 0xff),
        (unsigned char)((payload_len >> 8) & 0xff),
        (unsigned char)(payload_len & 0xff)
    };

    std::vector<uint8_t> record;
    record.reserve(sizeof(header) + payload_len); // avoid reallocations
    record.insert(record.end(), header, header + sizeof(header));
    record.insert(record.end(), iv.begin(), iv.end());
    record.insert(record.end(), ciphertext.begin(), ciphertext.end());
    record.insert(record.end(), tag.begin(), tag.end());

    return send_all(fd, record.data(), record.size());
}
bool recv_gcm_packet(int fd,
                     vector<unsigned char>& iv,
                     vector<unsigned char>& tag,
                     vector<unsigned char>& ciphertext,
                     size_t iv_len,
                     size_t tag_len) {
    unsigned char header[5];
    if (!recv_all(fd, header, sizeof(header))) return false;

    uint8_t content_type = header[0];
    uint16_t version = (header[1] << 8) | header[2];
    uint16_t payload_len = (header[3] << 8) | header[4];

    // Basic sanity checks
    if (content_type != TLS_APPLICATION_DATA) return false;
    if (version != TLS_VERSION) return false;
    if (payload_len < iv_len + tag_len) return false;

    vector<unsigned char> payload(payload_len);
    if (!recv_all(fd, payload.data(), payload_len)) return false;

    // Split into IV | ciphertext | tag
    iv.assign(payload.begin(), payload.begin() + iv_len);
    tag.assign(payload.end() - tag_len, payload.end());
    ciphertext.assign(payload.begin() + iv_len, payload.end() - tag_len);

    return true;
}
