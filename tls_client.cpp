// client.cpp
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <iostream>
#include <vector>

#include "utility.h"

#define PORT 5555
#define SERVER_IP "127.0.0.1"
#define BUF_SIZE 8192

using namespace std;

// --- main client flow ---
int main() {
    OpenSSL_add_all_algorithms();

    // 1) generate client key
    EVP_PKEY* client_key = generate_ec_key();
    if (!client_key) { cerr << "client keygen fail\n"; return 1; }

    // 1) connect
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); return 1; }
    sockaddr_in serv_addr{};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr);
    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) { perror("connect"); close(sock); return 1; }
    cout << "[Client] connected to server\n";

    // 2) send client pubkey
    if (!send_pubkey(sock, client_key)) { cerr << "[Client] send pubkey fail\n"; close(sock); return 1; }

    // 5) receive server pubkey
    EVP_PKEY* server_pub = recv_pubkey(sock);
    if (!server_pub) { cerr << "[Client] recv server pubkey fail\n"; close(sock); return 1; }

    // 6) derive shared secret and AES key
    vector<unsigned char> secret = derive_shared_secret(client_key, server_pub);
    vector<unsigned char> salt(32, 0); // all zeros for first handshake
    vector<unsigned char> aes_key;
    try {
        //aes_key = sha256(secret); // 32 bytes
        aes_key = hkdf_extract_and_expand(salt, secret, "TLS handshake key", 32);
    } catch (const std::runtime_error& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }

    cout << "[Client] derived secret (sha256): ";
    for (auto b : aes_key) printf("%02x", b);
    cout << endl;

    // 7) send READY encrypted
    vector<unsigned char> iv, tag, ciphertext;
    if (!aes_gcm_encrypt(aes_key, "READY", ciphertext, iv, tag)) { cerr << "[Client] encrypt READY fail\n"; }
    if (!send_gcm_packet(sock, iv, tag, ciphertext)) { cerr << "[Client] send READY fail\n"; }

    // 10) receive OK encrypted
    vector<unsigned char> iv2, tag2, cipher2;
    // AES-GCM typically uses 12 bytes IV, 16 bytes tag
    if (!recv_gcm_packet(sock, iv2, tag2, cipher2, GCM_IV_LEN, GCM_TAG_LEN)) { cerr << "[Client] recv OK fail\n"; }
    string reply;
    if (!aes_gcm_decrypt(aes_key, cipher2, iv2, tag2, reply)) { cerr << "[Client] decrypt OK fail\n"; }
    else cout << "[Client] server says: " << reply << endl;

    EVP_PKEY_free(client_key);
    EVP_PKEY_free(server_pub);
    close(sock);
    return 0;
}
