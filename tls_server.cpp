// server.cpp
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

using namespace std;

// --- main server flow ---
int main() {
    OpenSSL_add_all_algorithms();

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    // 1) bind and listen
    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); close(server_fd); return 1; }
    if (listen(server_fd, 1) < 0) { perror("listen"); close(server_fd); return 1; }

    cout << "[Server] listening on port " << PORT << endl;
    int client_fd = accept(server_fd, nullptr, nullptr);
    if (client_fd < 0) { perror("accept"); close(server_fd); return 1; }
    cout << "[Server] client connected\n";

    // 3) receive client pubkey
    EVP_PKEY* client_pub = recv_pubkey(client_fd);
    if (!client_pub) { cerr << "[Server] failed recv client pubkey\n"; close(client_fd); close(server_fd); return 1; }

    // 4) gen server key and send pubkey
    EVP_PKEY* server_key = generate_ec_key();
    if (!server_key) { cerr << "server keygen fail\n"; EVP_PKEY_free(client_pub); close(client_fd); close(server_fd); return 1; }
    if (!send_pubkey(client_fd, server_key)) { cerr << "[Server] failed send pubkey\n"; EVP_PKEY_free(client_pub); EVP_PKEY_free(server_key); close(client_fd); close(server_fd); return 1; }

    // 6) derive shared secret & make AES key
    vector<unsigned char> secret = derive_shared_secret(server_key, client_pub);
    vector<unsigned char> salt(32, 0); // all zeros for first handshake
    vector<unsigned char> aes_key;
    try {
        //aes_key = sha256(secret); // 32 bytes
        aes_key = hkdf_extract_and_expand(salt, secret, "TLS handshake key", 32);
    } catch (const std::runtime_error& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }

    cout << "[Server] derived secret (sha256): ";
    for (auto b : aes_key) printf("%02x", b);
    cout << endl;

    // 8) receive READY encrypted
    vector<unsigned char> iv, tag, ciphertext;
    // AES-GCM typically uses 12 bytes IV, 16 bytes tag
    if (!recv_gcm_packet(client_fd, iv, tag, ciphertext, GCM_IV_LEN, GCM_TAG_LEN)) { cerr << "[Server] failed recv gcm packet\n"; }
    string msg;
    if (!aes_gcm_decrypt(aes_key, ciphertext, iv, tag, msg)) { cerr << "[Server] decrypt READY failed\n"; }
    else cout << "[Server] client says: " << msg << endl;

    // 9) reply OK encrypted
    vector<unsigned char> iv2, tag2, cipher2;
    aes_gcm_encrypt(aes_key, "OK", cipher2, iv2, tag2);
    send_gcm_packet(client_fd, iv2, tag2, cipher2);

    EVP_PKEY_free(server_key);
    EVP_PKEY_free(client_pub);
    close(client_fd);
    close(server_fd);
    return 0;
}
