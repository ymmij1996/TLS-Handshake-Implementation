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

using namespace std;

// --- main client flow ---
int main() {
    OpenSSL_add_all_algorithms();

    uint64_t server_seq = 0;
    uint64_t client_seq = 0;
    EVP_PKEY* client_key = NULL, *server_pub = NULL;
    int sock = -1;
    try {
        // 1) generate client key
        client_key = generate_ec_key();
        if (!client_key) throw runtime_error("keygen fail");

        // 1) connect
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) throw runtime_error("socket fail");
        sockaddr_in serv_addr{};
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(PORT);
        inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr);
        if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) throw runtime_error("connect fail");
        cout << "[Client] connected to server\n";

        // 2) send client pubkey
        if (!send_pubkey(sock, client_key)) throw runtime_error("send pubkey fail\n");

        // 5) receive server pubkey
        server_pub = recv_pubkey(sock);
        if (!server_pub) throw runtime_error("recv server pubkey fail\n");

        // 6) derive shared secret and AES key
        vector<unsigned char> secret = derive_shared_secret(client_key, server_pub);
        vector<unsigned char> salt(32, 0); // all zeros for first handshake
        //aes_key = sha256(secret); // 32 bytes
        //aes_key = hkdf_extract_and_expand(salt, secret, "TLS handshake key", 32);
        
        vector<unsigned char> server_iv  = hkdf_extract_and_expand(salt, secret, HKDF_SERVER_VI_LABEL, GCM_IV_LEN);
        vector<unsigned char> client_iv  = hkdf_extract_and_expand(salt, secret, HKDF_CLIENT_VI_LABEL, GCM_IV_LEN);
        vector<unsigned char> server_key = hkdf_extract_and_expand(salt, secret, HKDF_SERVER_KEY_LABEL, 32);
        vector<unsigned char> client_key = hkdf_extract_and_expand(salt, secret, HKDF_CLIENT_KEY_LABEL, 32);
        cout << "[Client] server key: " << server_key << endl;
        cout << "[Client] client key: " << client_key << endl;

        // 7) send READY encrypted
        vector<unsigned char> tag, cipher, expected_iv, write_iv;
        string send_msg, recv_msg;
        uint64_t server_seq = 0, client_seq = 0;
        
        send_msg = "READY";
        write_iv = make_record_iv(client_iv, client_seq++);
        if (!aes_gcm_encrypt(client_key, send_msg, cipher, write_iv, tag)) throw runtime_error("encrypt READY fail");
        if (!send_gcm_packet(sock, tag, cipher)) throw runtime_error("send READY fail");
        cout << "[Client] client sends: " << send_msg << endl;

        // 10) receive OK encrypted
        expected_iv = make_record_iv(server_iv, server_seq++);
        if (!recv_gcm_packet(sock, tag, cipher, GCM_TAG_LEN)) throw runtime_error("recv OK fail");
        if (!aes_gcm_decrypt(server_key, cipher, expected_iv, tag, recv_msg)) throw runtime_error("decrypt OK fail");
        cout << "[Client] server says: " << recv_msg << endl;

        expected_iv = make_record_iv(server_iv, server_seq++);
        if (!recv_gcm_packet(sock, tag, cipher, GCM_TAG_LEN)) throw runtime_error("recv OK fail");
        if (!aes_gcm_decrypt(server_key, cipher, expected_iv, tag, recv_msg)) throw runtime_error("decrypt OK fail");
        cout << "[Client] server says: " << recv_msg << endl;

        send_msg = "Got it.";
        write_iv = make_record_iv(client_iv, client_seq++);
        if (!aes_gcm_encrypt(client_key, send_msg, cipher, write_iv, tag)) throw runtime_error("encrypt READY fail");
        if (!send_gcm_packet(sock, tag, cipher)) throw runtime_error("send READY fail");
        cout << "[Client] client sends: " << send_msg << endl;

    } catch (const runtime_error& e) {
        cerr << "[Client Error] " << e.what() << endl;
        EVP_PKEY_free(client_key);
        EVP_PKEY_free(server_pub);
        close(sock);
        return 1;
    }

    EVP_PKEY_free(client_key);
    EVP_PKEY_free(server_pub);
    close(sock);
    return 0;
}
