#pragma once
#include <openssl/evp.h>
#include <vector>
#include <string>
#include <iomanip>

#define BUF_SIZE 8192
constexpr uint8_t TLS_APPLICATION_DATA = 23;   // 0x17
constexpr uint16_t TLS_VERSION = 0x0303;       // TLS 1.2/1.3 wire version
constexpr size_t GCM_IV_LEN = 12;
constexpr size_t GCM_TAG_LEN = 16;
#define HKDF_SERVER_VI_LABEL  "tls13 server iv"
#define HKDF_CLIENT_VI_LABEL  "tls13 client iv"
#define HKDF_SERVER_KEY_LABEL "tls13 server key"
#define HKDF_CLIENT_KEY_LABEL "tls13 client key"

typedef struct vec_print{
    std::string var;
    std::vector<unsigned char> vec;
    vec_print (std::vector<unsigned char> vec=std::vector<unsigned char>(), std::string str=""): vec(vec), var(str) {}
} vec_print;
#define PRINT_VEC(vec) vec_print(vec, #vec)
std::ostream& operator<<(std::ostream& os, const vec_print& vec_print);

bool send_pubkey(int fd, EVP_PKEY* pkey);
EVP_PKEY* recv_pubkey(int fd);
EVP_PKEY* generate_ec_key();
std::vector<unsigned char> derive_shared_secret(EVP_PKEY* priv_key, EVP_PKEY* peer_pubkey);
std::vector<unsigned char> sha256(const std::vector<unsigned char>& data);
std::vector<unsigned char> hkdf_extract_and_expand(
    const std::vector<unsigned char>& salt,
    const std::vector<unsigned char>& input_key_material,
    const std::string& info,
    size_t length
);

std::vector<unsigned char> make_record_iv(const std::vector<unsigned char>& base_iv, uint64_t seq_num);

bool send_all(int fd, const void* data, size_t len);
bool recv_all(int fd, void* data, size_t len);

bool aes_gcm_encrypt(const std::vector<unsigned char>& key,
                     const std::string& plaintext,
                     std::vector<unsigned char>& ciphertext,
                     std::vector<unsigned char>& iv,
                     std::vector<unsigned char>& tag);

bool aes_gcm_decrypt(const std::vector<unsigned char>& key,
                     const std::vector<unsigned char>& ciphertext,
                     const std::vector<unsigned char>& iv,
                     const std::vector<unsigned char>& tag,
                     std::string& plaintext);

bool send_gcm_packet(int fd,
                     const std::vector<unsigned char>& tag,
                     const std::vector<unsigned char>& ciphertext);

bool recv_gcm_packet(int fd,
                     std::vector<unsigned char>& tag,
                     std::vector<unsigned char>& ciphertext,
                     size_t tag_len);