// client.cpp
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <unistd.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>

#include <cstring>
#include <iostream>
#include <vector>
#include <memory>

#include "utility.h"
#include "tls_impl.h"

#define PORT 5555
#define SERVER_IP "127.0.0.1"

using namespace std;


int main() {
    if (CRYPTO_secure_malloc_init(65536, 4096) != 1) {
        cerr << "Could not initialize secure heap. Check permissions (ulimit -l)." << endl;
        return 1;
    }
    OpenSSL_add_all_algorithms();

    EVP_PKEY* client_ephemeral_key = NULL, *server_ephemeral_pub = NULL, *server_static_pub;
    int sock = -1;
    string send_msg, recv_msg;
    uint64_t server_seq = 0, client_seq = 0;
    vector<X509*> certs;
    
    unique_ptr<X509_STORE, decltype(&X509_STORE_free)> global_trusted_store_ptr(X509_STORE_new(), X509_STORE_free);
    X509* root = load_cert("root.crt");
    X509_STORE_add_cert(global_trusted_store_ptr.get(), root);
    X509_free(root);

    try {
        // generate client key
        client_ephemeral_key = generate_ec_key();
        if (!client_ephemeral_key) throw runtime_error("keygen fail");

        // connect
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) throw runtime_error("socket fail");
        sockaddr_in serv_addr{};
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(PORT);
        inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr);
        if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) throw runtime_error("connect fail");
        cout << "[Client] connected to server\n";

        // send client pubkey
        if (!send_pubkey(sock, client_ephemeral_key)) throw runtime_error("send pubkey fail\n");

        // receive certificates and verify
        server_static_pub = recv_verify_cert(sock, global_trusted_store_ptr.get());
        if (!server_static_pub) throw runtime_error("verify_incoming fail\n");
        // verify and decode server public key
        server_ephemeral_pub = recv_and_verify_signed_key(sock, server_static_pub);

        // derive shared secret and AES key
        SecureVector secret = derive_shared_secret(client_ephemeral_key, server_ephemeral_pub);
        if (secret.size() <= 0) throw runtime_error("derive_shared_secret fail");

        SecureVector salt(32, 0); // all zeros for first handshake, salt is part of the input so still using SecureVector here
        SecureVector server_iv  = hkdf_extract_and_expand(salt, secret, HKDF_SERVER_VI_LABEL, GCM_IV_LEN);
        SecureVector client_iv  = hkdf_extract_and_expand(salt, secret, HKDF_CLIENT_VI_LABEL, GCM_IV_LEN);
        SecureVector server_key = hkdf_extract_and_expand(salt, secret, HKDF_SERVER_KEY_LABEL, 32);
        SecureVector client_key = hkdf_extract_and_expand(salt, secret, HKDF_CLIENT_KEY_LABEL, 32);

        // send READY encrypted
        send_msg = "READY";
        if (!aes_gcm_encrypt_send(sock, send_msg, client_key, client_iv, client_seq)) throw runtime_error("encrypt_send fail");
        cout << "[Client] client sends: " << send_msg << endl;

        // receive OK encrypted
        recv_msg = "";
        if (!aes_gcm_recv_decrypt(sock, recv_msg, server_key, server_iv, server_seq)) throw runtime_error("recv_decrypt fail");
        cout << "[Client] server says: " << recv_msg << endl;

        recv_msg = "";
        if (!aes_gcm_recv_decrypt(sock, recv_msg, server_key, server_iv, server_seq)) throw runtime_error("recv_decrypt fail");
        cout << "[Client] server says: " << recv_msg << endl;

        send_msg = "Got it.";
        if (!aes_gcm_encrypt_send(sock, send_msg, client_key, client_iv, client_seq)) throw runtime_error("encrypt_send fail");
        cout << "[Client] client sends: " << send_msg << endl;

    } catch (const runtime_error& e) {
        cerr << "[Client Error] " << e.what() << endl;
        EVP_PKEY_free(client_ephemeral_key);
        EVP_PKEY_free(server_ephemeral_pub);
        EVP_PKEY_free(server_static_pub);
        close(sock);
        return 1;
    }

    EVP_PKEY_free(client_ephemeral_key);
    EVP_PKEY_free(server_ephemeral_pub);
    EVP_PKEY_free(server_static_pub);
    close(sock);
    return 0;
}
