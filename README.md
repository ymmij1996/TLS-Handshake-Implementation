# TLS-Handshake-Implementation
* This project simulates TLS handshake using ECDHE key exchange and encrypt using AES-GCM afterward. Note that the CA certificate sent and verification part is completely skipped compared to the formal TLS handshake for simplicity. 

<h2> Testing Environment </h2>

* Testing on ubuntu with wsl
  ```sh
  ~/TLS-Handshake-Implementation$ lsb_release -a
  No LSB modules are available.
  Distributor ID: Ubuntu
  Description:    Ubuntu 24.04.2 LTS
  Release:        24.04
  Codename:       noble
  ```

<h2> How to build</h2>

* install OpenSSL library (install tcpdump optionally as well)
  ```sh
  apt install libssl-dev
  apt  install tcpdump
  ```
* compile server
  ```sh
  g++ tls_server.cpp utility.cpp -lssl -lcrypto -o tls_server
  ```
* compile client
  ```sh
  g++ tls_client.cpp utility.cpp -lssl -lcrypto -o tls_client
  ```

<h2> Testing </h2>

* open a command prompt running server
  ```sh
  ./tls_server
  ```

* open another command prompt running client
  ```sh
  ./tls_client
  ```
* the result printing on the command prompt
  ```sh
  ~/TLS-Handshake-Implementation$ ./tls_server
  [Server] listening on port 5555
  [Server] client connected
  [Server] server key:  {32 bytes, hex: de72c6ddcce071f6bf9f8a42be6ac18789216598fa3dafc2ffb00ac0a2e65f32}
  [Server] client key:  {32 bytes, hex: 0a7f7f18019f7d33610fd3ba5358e5acbcf3f41cac171c7b3058d2441c47e2c2}
  [Server] client says: READY
  [Server] server sends: OK
  [Server] server sends: something interesting but only you can know
  [Server] client says: Got it.
  ```
  ```sh
  ~/TLS-Handshake-Implementation$ ./tls_client
  [Client] connected to server
  [Client] server key:  {32 bytes, hex: de72c6ddcce071f6bf9f8a42be6ac18789216598fa3dafc2ffb00ac0a2e65f32}
  [Client] client key:  {32 bytes, hex: 0a7f7f18019f7d33610fd3ba5358e5acbcf3f41cac171c7b3058d2441c47e2c2}
  [Client] client sends: READY
  [Client] server says: OK
  [Client] server says: something interesting but only you can know
  [Client] client sends: Got it.
  ```
* optionally, we can use tcpdump before running the client and server probrams to dump the content of the packets
  ```sh
  ~/TLS-Handshake-Implementation$ tcpdump port 5555 -i <your interface name> -w tls.pcap
  ```
<h2> Explanation </h2>

* Wireshark Trace. Packet numbers correspond to the captured tls.pcap file.

<img width="2542" height="451" alt="image" src="https://github.com/user-attachments/assets/cfe7643f-fb95-4fc2-a6a6-4beb6ff0ca89" />

  ```sh
  Client                               Server
  |---- TCP 3-way handshake --------------->| Packets 1–3: TCP three-way handshake
  |---- [len=pubkey] + pubkey ------------->| Packet 4: Client sends [length + public key]
  |<--- [len=pubkey] + pubkey --------------| Packet 6: Server sends [length + public key]
  |---- "READY" (AES-GCM encrypted) ------->| Packet 8: Client sends "READY" encrypted with AES-GCM
  |<--- "OK"    (AES-GCM encrypted) --------| Packet 9: Server replies "OK" encrypted with AES-GCM
  ```

* using wireshark to open tls.pcap we just recorded, we can observe that the first three packets are TCP three-way handshake by the server accepting and the client connecting on their sockets.

  ```sh
  // client 
  connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr))
  // server
  accept(server_fd, nullptr, nullptr)
  ```

* Afterward, the client sent the fourth packet to the server with its public key. The first 4 bytes represents the length of the client public key (DER-encoded key) followed by the key itself. The server sent Packet 6 to the client with its key length and public key as well and they both calculate the same secret (The Diffie-Hellman shared secret) which is passed through HKDF (RFC 5869). For Packet 8 and Packet 9, the server and the client were able to use AES-GCM to encrypt their message.

* For generating a deterministic initialization vector (IV), the following formula is applied computing separately for each direction and message:
  ```sh
  IV = base_iv ⊕ sequence_number
  ```

<h2> Security Notes</h2>
This project is "educational only":

* It skips certificate verification and CA trust chains.

* It uses a fixed salt in HKDF (not randomized per session).

These shortcuts are intentional to make the handshake logic clear, but would not be secure in production.
