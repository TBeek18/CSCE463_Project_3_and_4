import socket
import threading
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

#save rsa keys to server .pem files
rsaKey = RSA.generate(2048)

privateKey = rsaKey.export_key()
with open("server_private.pem", "wb") as file: #save private key to server_private.pem in write binary mode
  file.write(privateKey)

publicKey = rsaKey.publickey().export_key()
with open("server_public.pem", "wb") as file:
  file.write(publicKey)

#load private key of server
with open("server_private.pem", "rb") as file:
  server_private_key = RSA.import_key(file.read())

rsa_cipher = PKCS1_OAEP.new(server_private_key)

#create server side TCP socket
serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
address = ('localhost', 8080)
serverSocket.bind(address)
maxQueuedConnections = 5 #number of incoming connections server can wait on before new connections are rejected
serverSocket.listen(maxQueuedConnections)
while True:
  clientSocket, clientAddress = serverSocket.accept()
  print("New connection from " + str(clientAddress) + " established.")
  try:
    while True: #run until client disconnects or sends 'quit'
      #Receive client message
      encrypted_message = clientSocket.recv(1024)
      if not encrypted_message or encrypted_message.decode('utf-8').lower() == "quit": #if client disconnects or sends 'quit'
        break
      try:
        decrypted_message = rsa_cipher.decrypt(encrypted_message).decode('utf-8')
      except ValueError:
        decrypted_message = "[Decryption Failed]"
      print(f"Received from client: {decrypted_message}")
      #send response to client
      response = "Message received"
      clientSocket.sendall(response.encode('utf-8'))
  except ConnectionResetError:
    print("Client disconnected")
  finally:
    clientSocket.close()
    print("Connection closed")



