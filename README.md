# TLS-Handshake-Implementation
* This project simulates TLS handshake using ECDHE key exchange and encrypt using AES-GCM afterward. Note that the CA certificate sent and verification part is completely skipped compared to the formal TLS handshake. 

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
  [Server] derived secret (hkdf): 9f85cbb78514b178959c7c78e6f1862a14c06feeff6c72a06fb964882b829910
  [Server] client says: READY
  ```
  ```sh
  ~/TLS-Handshake-Implementation$ ./tls_client
  [Client] connected to server
  [Client] derived secret (hkdf): 16014910e40f1a5c7f8d2364cc15d79d5efc9af02f1e539313af5561aef193b3
  [Client] server says: OK
  ```
  * optionally, we can use tcpdump before running the client and server probrams to dump the content of the packets
  ```sh
  ~/TLS-Handshake-Implementation$ tcpdump port 5555 -i <your interface name> -w tls.pcap
  ```
  <h2> Explaination </h2>

  * wireshark screenshot
<img width="2555" height="385" alt="image" src="https://github.com/user-attachments/assets/8fc6f87b-ec1b-4887-bb4b-8ca15ce88640" />

 * using wireshark to open tls.pcap we just recorded, we can observe that the first three packets are TCP three-way handshake by the server accepting and the client connecting on their sockets.

  ```sh
  // client 
  connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr))
  // server
  accept(server_fd, nullptr, nullptr)
  ```

 * Afterward, the client sent the fourth packet to the server with its public key. The server sent the sixth packet to the client with its public key as well and they both calculate the same secret and its corresponding AES symmetric keys which others do not know. For the eighth and the ninth packets, the server and the client were able to use AES-GCM key to encrypt their message.
  
