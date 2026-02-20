#pragma once
#include <openssl/evp.h>
#include <openssl/err.h>
#include <vector>
#include <string>
#include <iomanip>

#define BUF_SIZE 8192
constexpr unsigned char  TLS_APPLICATION_DATA = 23;   // 0x17
constexpr uint16_t TLS_VERSION = 0x0303;       // TLS 1.2/1.3 wire version
constexpr size_t GCM_IV_LEN = 12;
constexpr size_t GCM_TAG_LEN = 16;
#define HKDF_SERVER_VI_LABEL  "tls13 server iv"
#define HKDF_CLIENT_VI_LABEL  "tls13 client iv"
#define HKDF_SERVER_KEY_LABEL "tls13 server key"
#define HKDF_CLIENT_KEY_LABEL "tls13 client key"

// X.509
void simulate_x509();
X509* load_cert(const std::string& filename);
EVP_PKEY* load_private_key(const std::string& filename);

bool send_pubkey(int fd, EVP_PKEY* pkey);

EVP_PKEY* recv_pubkey(int fd);
bool send_cert_chain_signed_pubkey(int fd, const std::vector<X509*>& certs, EVP_PKEY* ephemeral_pkey, EVP_PKEY* static_priv_key);

EVP_PKEY* recv_verify_cert(int sock, X509_STORE* global_trusted_store);
EVP_PKEY* recv_and_verify_signed_key(int sock, EVP_PKEY* server_static_pub);

// ECDHE
EVP_PKEY* generate_ec_key();
std::vector<unsigned char> derive_shared_secret(EVP_PKEY* priv_key, EVP_PKEY* peer_pubkey);
std::vector<unsigned char> sha256(const std::vector<unsigned char>& data);
std::vector<unsigned char> hkdf_extract_and_expand(
    const std::vector<unsigned char>& salt,
    const std::vector<unsigned char>& input_key_material,
    const std::string& info,
    size_t length
);

// AES GCM
std::vector<unsigned char> make_record_iv(const std::vector<unsigned char>& base_iv, uint64_t seq_num);

bool aes_gcm_encrypt_send(int sock, std::string& send_msg, std::vector<unsigned char>& key, std::vector<unsigned char>& base_iv, uint64_t& seq);
bool aes_gcm_recv_decrypt(int sock, std::string& recv_msg, std::vector<unsigned char>& key, std::vector<unsigned char>& base_iv, uint64_t& seq);
