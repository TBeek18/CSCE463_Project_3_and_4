import socket
import threading
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

#save rsa keys to client .pem files
rsaKey = RSA.generate(2048)

privateKey = rsaKey.export_key()
with open("client_private.pem", "wb") as file: #save private key to client_private.pem in write binary mode
  file.write(privateKey)

publicKey = rsaKey.publickey().export_key()
with open("client_public.pem", "wb") as file:
  file.write(publicKey)

#load public key of server
with open("server_public.pem", "rb") as file:
  server_public_key = RSA.import_key(file.read())
  
rsa_cipher = PKCS1_OAEP.new(server_public_key)

#create client side TCP socket
clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
address = ('localhost', 8080)
clientSocket.connect(address)
try:
  while True:
    #send message to server
    message = input("Enter message: ")
    encrypted_message = rsa_cipher.encrypt(message.encode('utf-8'))
    clientSocket.sendall(encrypted_message)
    #Receive server response
    response = clientSocket.recv(1024)
    print(f"Received from server: "+ str(response.decode('utf-8')))
except KeyboardInterrupt:
  print("Client disconnected")
finally:
  clientSocket.close()