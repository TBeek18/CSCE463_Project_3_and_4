import socket
import threading
import os
from Crypto.PublicKey import RSA

#save rsa keys to client .pem files
rsaKey = RSA.generate(2048)

privateKey = rsaKey.export_key()
with open("client_private.pem", "wb") as file: #save private key to client_private.pem in write binary mode
  file.write(privateKey)

publicKey = rsaKey.publickey().export_key()
with open("client_public.pem", "wb") as file:
  file.write(publicKey)

#create client side TCP socket
clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
address = ('localhost', 8080)
clientSocket.connect(address)
try:
  while True:
    #send message to server
    message = input("Enter message: ")
    clientSocket.sendall(message.encode('utf-8'))
    #Receive server response
    response = clientSocket.recv(1024)
    print(f"Received from server: "+ str(response.decode('utf-8')))
except KeyboardInterrupt:
  print("Client disconnected")
finally:
  clientSocket.close()