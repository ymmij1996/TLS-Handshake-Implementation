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
#include "tls_impl.h"

#define PORT 5555

using namespace std;


int main() {
    if (CRYPTO_secure_malloc_init(65536, 4096) != 1) { // (capacity, chunk size)
        cerr << "Could not initialize secure heap. Check permissions (ulimit -l)." << endl;
        return 1;
    }
    OpenSSL_add_all_algorithms();

    simulate_x509();

    vector<X509*> certs;
    certs.push_back(load_cert("server.crt"));       // Leaf first
    certs.push_back(load_cert("intermediate.crt")); // Intermediate second

    int server_fd = -1, client_fd = -1;
    EVP_PKEY* client_pub = NULL, *ephemeral_key = NULL;
    string send_msg, recv_msg;
    uint64_t server_seq = 0, client_seq = 0;
    EVP_PKEY* static_priv_key = load_private_key("server.key");

    try {
        server_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd < 0) throw runtime_error("socket fail");

        int opt = 1;
        setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(PORT);

        // bind and listen
        if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) throw runtime_error("bind fail");
        if (listen(server_fd, 1) < 0) throw runtime_error("listen fail");

        cout << "[Server] listening on port " << PORT << endl;
        client_fd = accept(server_fd, nullptr, nullptr);
        if (client_fd < 0) throw runtime_error("accept fail");
        cout << "[Server] client connected\n";

        // receive client pubkey
        client_pub = recv_pubkey(client_fd);
        if (!client_pub) throw runtime_error("failed recv client pubkey");

        // load server private static key
        // note that static public key is not calculated in runtime, it is embedded in server.cst
        if (!static_priv_key) throw runtime_error("failed load private key");

        // generate ephemeral public and private key
        ephemeral_key = generate_ec_key();
        if (!ephemeral_key) throw runtime_error("keygen fail");
        
        // send intermediate CA and server certificates and signed server ephemeral public key
        if (!send_cert_chain_signed_pubkey(client_fd, certs, ephemeral_key, static_priv_key)) {
            throw runtime_error("send_cert_chain_signed_pubkey failed");
        }

        // derive shared secret
        SecureVector secret = derive_shared_secret(ephemeral_key, client_pub);
        if (secret.size() <= 0) {
            throw runtime_error("derive_shared_secret fail");
        }

        SecureVector salt(32, 0); // all zeros for first handshake
        SecureVector server_iv  = hkdf_extract_and_expand(salt, secret, HKDF_SERVER_VI_LABEL, GCM_IV_LEN);
        SecureVector client_iv  = hkdf_extract_and_expand(salt, secret, HKDF_CLIENT_VI_LABEL, GCM_IV_LEN);
        SecureVector server_aes_key = hkdf_extract_and_expand(salt, secret, HKDF_SERVER_KEY_LABEL, 32);
        SecureVector client_aes_key = hkdf_extract_and_expand(salt, secret, HKDF_CLIENT_KEY_LABEL, 32);

        // receive READY encrypted
        recv_msg = "";
        if (!aes_gcm_recv_decrypt(client_fd, recv_msg, client_aes_key, client_iv, client_seq)) throw runtime_error("decrypt_recv fail");
        cout << "[Server] client says: " << recv_msg << endl;

        // reply OK encrypted
        send_msg = "OK";
        if (!aes_gcm_encrypt_send(client_fd, send_msg, server_aes_key, server_iv, server_seq)) throw runtime_error("encrypt_send fail");
        cout << "[Server] server sends: " << send_msg << endl;

        send_msg = "something interesting but only you can know";
        if (!aes_gcm_encrypt_send(client_fd, send_msg, server_aes_key, server_iv, server_seq)) throw runtime_error("encrypt_send fail");
        cout << "[Server] server sends: " << send_msg << endl;

        recv_msg = "";
        if (!aes_gcm_recv_decrypt(client_fd, recv_msg, client_aes_key, client_iv, client_seq)) throw runtime_error("decrypt_recv fail");
        cout << "[Server] client says: " << recv_msg << endl;

    } catch (const runtime_error& e) {
        cerr << "[Server Error] " << e.what() << endl;
        for (X509* c : certs) X509_free(c);
        close(server_fd);
        close(client_fd);
        EVP_PKEY_free(client_pub);
        EVP_PKEY_free(ephemeral_key);
        EVP_PKEY_free(static_priv_key);
        return 1;
    }
    for (X509* c : certs) X509_free(c);
    EVP_PKEY_free(ephemeral_key);
    EVP_PKEY_free(client_pub);
    EVP_PKEY_free(static_priv_key);
    close(client_fd);
    close(server_fd);
    return 0;
}
