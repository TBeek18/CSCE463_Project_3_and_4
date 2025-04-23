# CSCE463 - Project 3/4 - Secure Chat Application

## Overview
This is a secure, real-time chat application implemented in Python using TCP sockets and Public Key Infrastructure (PKI). Messages
are encrypted using AES (symmetric encryption), with session keys secured via RSA (asymmetric encryption). Each message is digitally
signed and verified to ensure authenticity and integrity

## File Overview
- The `server.py` file is a secure chat server that handles multiple clients.
- The `client.py` file is a client interface to send and receive secure messages.
- All of the `.pem` files are the automatically generated RSA keys.

## Requirements
To interact with this application, please clone the repository to your computer. Navigate to the directory where the project files are stored and run `pip install pycryptodome` in the terminal.

## How to Run
First, run `python server.py` within that same directory in your terminal. This will start up the server application. Then, in a new
terminal but in the same directory, run `python client.py`. Enter the following information:
- Server's IP Address: `127.0.0.1`
- Name: `yourname`

In a new terminal but in the same directory, run `python client.py` and repeat the above process, putting in a different name. Once both
clients are connected, go to either one of the client terminals, type a message, and hit Enter. This message will be sent to the server
and the server will then send it to the other client that is running. Verify that this works. 

To exit the clients, type `exit` in the client terminals.

To exit the server, type `shutdown` in the server terminal.