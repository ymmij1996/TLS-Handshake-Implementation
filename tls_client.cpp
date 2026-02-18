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
    OpenSSL_add_all_algorithms();

    EVP_PKEY* client_key = NULL, *server_pub = NULL, *server_static_pub;
    int sock = -1;
    string send_msg, recv_msg;
    uint64_t server_seq = 0, client_seq = 0;
    vector<X509*> certs;
    
    unique_ptr<X509_STORE, decltype(&X509_STORE_free)> global_trusted_store_ptr(X509_STORE_new(), X509_STORE_free);
    X509* root = load_cert("root.crt");
    X509_STORE_add_cert(global_trusted_store_ptr.get(), root);
    X509_free(root);

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
        //server_pub = recv_pubkey(sock);
        //if (!server_pub) throw runtime_error("recv server pubkey fail\n");
        certs = recv_cert(sock);
        if (certs.size() != 2) { // our implementation uses excatly 2 cert
            throw runtime_error("recv certificate fail\n");
        }

        server_static_pub = verify_incoming(global_trusted_store_ptr.get(), certs);
        if (!server_static_pub) throw runtime_error("verify_incoming fail\n");

        server_pub = recv_and_verify_signed_key(sock, server_static_pub);

        // 6) derive shared secret and AES key
        vector<unsigned char> secret = derive_shared_secret(client_key, server_pub);
        if (secret.size() <= 0) throw runtime_error("derive_shared_secret fail");

        vector<unsigned char> salt(32, 0); // all zeros for first handshake
        vector<unsigned char> server_iv  = hkdf_extract_and_expand(salt, secret, HKDF_SERVER_VI_LABEL, GCM_IV_LEN);
        vector<unsigned char> client_iv  = hkdf_extract_and_expand(salt, secret, HKDF_CLIENT_VI_LABEL, GCM_IV_LEN);
        vector<unsigned char> server_key = hkdf_extract_and_expand(salt, secret, HKDF_SERVER_KEY_LABEL, 32);
        vector<unsigned char> client_key = hkdf_extract_and_expand(salt, secret, HKDF_CLIENT_KEY_LABEL, 32);

        // 7) send READY encrypted
        send_msg = "READY";
        if (!aes_gcm_encrypt_send(sock, send_msg, client_key, client_iv, client_seq)) throw runtime_error("encrypt_send fail");
        cout << "[Client] client sends: " << send_msg << endl;

        // 10) receive OK encrypted
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
        EVP_PKEY_free(client_key);
        EVP_PKEY_free(server_pub);
        EVP_PKEY_free(server_static_pub);
        close(sock);
        return 1;
    }

    EVP_PKEY_free(client_key);
    EVP_PKEY_free(server_pub);
    EVP_PKEY_free(server_static_pub);
    close(sock);
    return 0;
}
