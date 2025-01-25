# Secure-Client-Server-Connection-Using-a-Distributed-Double-DES-D-DDES
## Assigment Overview

This Assigment implements a secure multi-client server-client application using Python. The communication between the server and clients is encrypted using the Data Encryption Standard (DES) in Cipher Block Chaining (CBC) mode. Additionally, the application employs Diffie-Hellman key exchange for secure key derivation and HMAC-SHA256 for ensuring data integrity and authenticity.

## Features

Multi-Client Support: The server can handle multiple clients concurrently using threading.
Secure Communication: Utilizes DES-CBC for encryption and HMAC-SHA256 for data integrity.
Diffie-Hellman Key Exchange: Establishes secure keys between the server and each client without transmitting them directly.
Session Management: Generates unique session tokens for each client to manage individual sessions securely.
Graceful Disconnects: Clients can disconnect gracefully, informing the server to clean up resources.

## Architecture

- Server (server.py):

Listens for incoming client connections.
Performs Diffie-Hellman key exchange with each client to derive unique DES keys (K1 for encryption/decryption and K2 for HMAC).
Sends an encrypted session token to the client.
Receives encrypted data from clients, verifies HMAC, decrypts the data, and aggregates numeric inputs from all clients.
Sends back the updated aggregate to clients securely.

- Client (client.py):

Connects to the server.
Engages in Diffie-Hellman key exchange to derive shared DES keys.
Receives and decrypts the session token from the server.
Sends numeric data to the server, encrypted and accompanied by an HMAC for integrity.
Receives and decrypts the aggregated result from the server.
