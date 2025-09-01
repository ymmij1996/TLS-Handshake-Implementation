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

    int server_fd = -1, client_fd = -1;
    EVP_PKEY* client_pub = NULL, *server_key = NULL;
    try {
        server_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd < 0) throw runtime_error("socket fail");

        int opt = 1;
        setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(PORT);

        // 1) bind and listen
        if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) throw runtime_error("bind fail");
        if (listen(server_fd, 1) < 0) throw runtime_error("listen fail");

        cout << "[Server] listening on port " << PORT << endl;
        client_fd = accept(server_fd, nullptr, nullptr);
        if (client_fd < 0) throw runtime_error("accept fail");
        cout << "[Server] client connected\n";

        // 3) receive client pubkey
        client_pub = recv_pubkey(client_fd);
        if (!client_pub) throw runtime_error("failed recv client pubkey");

        // 4) gen server key and send pubkey
        server_key = generate_ec_key();
        if (!server_key) throw runtime_error("keygen fail");
        if (!send_pubkey(client_fd, server_key)) throw runtime_error("failed send pubkey");

        // 6) derive shared secret & make AES key
        vector<unsigned char> secret = derive_shared_secret(server_key, client_pub);
        vector<unsigned char> salt(32, 0); // all zeros for first handshake
        //aes_key = sha256(secret); // 32 bytes
        //aes_key = hkdf_extract_and_expand(salt, secret, "TLS handshake key", 32);
        
        vector<unsigned char> server_iv  = hkdf_extract_and_expand(salt, secret, HKDF_SERVER_VI_LABEL, GCM_IV_LEN);
        vector<unsigned char> client_iv  = hkdf_extract_and_expand(salt, secret, HKDF_CLIENT_VI_LABEL, GCM_IV_LEN);
        vector<unsigned char> server_key = hkdf_extract_and_expand(salt, secret, HKDF_SERVER_KEY_LABEL, 32);
        vector<unsigned char> client_key = hkdf_extract_and_expand(salt, secret, HKDF_CLIENT_KEY_LABEL, 32);
        cout << "[Server] server key: " << server_key << endl;
        cout << "[Server] client key: " << client_key << endl;

        vector<unsigned char> tag, cipher, expected_iv, write_iv;
        string send_msg, recv_msg;
        uint64_t server_seq = 0, client_seq = 0;

        // 8) receive READY encrypted
        expected_iv = make_record_iv(client_iv, client_seq++);
        if (!recv_gcm_packet(client_fd, tag, cipher, GCM_TAG_LEN)) throw runtime_error("failed recv gcm packet");
        if (!aes_gcm_decrypt(client_key, cipher, expected_iv, tag, recv_msg)) throw runtime_error("decrypt READY failed");
        cout << "[Server] client says: " << recv_msg << endl;

        // 9) reply OK encrypted
        send_msg = "OK";
        write_iv = make_record_iv(server_iv, server_seq++);
        aes_gcm_encrypt(server_key, send_msg, cipher, write_iv, tag);
        send_gcm_packet(client_fd, tag, cipher);
        cout << "[Server] server sends: " << send_msg << endl;

        send_msg = "something interesting but only you can know";
        write_iv = make_record_iv(server_iv, server_seq++);
        aes_gcm_encrypt(server_key, send_msg, cipher, write_iv, tag);
        send_gcm_packet(client_fd, tag, cipher);
        cout << "[Server] server sends: " << send_msg << endl;

        expected_iv = make_record_iv(client_iv, client_seq++);
        if (!recv_gcm_packet(client_fd, tag, cipher, GCM_TAG_LEN)) throw runtime_error("failed recv gcm packet");
        if (!aes_gcm_decrypt(client_key, cipher, expected_iv, tag, recv_msg)) throw runtime_error("decrypt READY failed");
        cout << "[Server] client says: " << recv_msg << endl;

    } catch (const runtime_error& e) {
        cerr << "[Server Error] " << e.what() << endl; 
        close(server_fd);
        close(client_fd);
        EVP_PKEY_free(client_pub);
        EVP_PKEY_free(server_key);
        return 1;
    }
    EVP_PKEY_free(server_key);
    EVP_PKEY_free(client_pub);
    close(client_fd);
    close(server_fd);
    return 0;
}
