import socket
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import os
import sys

client_active = True

def connect_to_server():
  # Generate client keys if not present
  if not os.path.exists('client_private.pem') or not os.path.exists('client_public.pem'):
    key = RSA.generate(2048)
    with open('client_private.pem', 'wb') as f:
      f.write(key.export_key())
    with open('client_public.pem', 'wb') as f:
      f.write(key.publickey().export_key())

  client_private_key = RSA.import_key(open('client_private.pem', 'rb').read())
  client_public_key = RSA.import_key(open('client_public.pem', 'rb').read())

  client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  server_host = input("Enter server IP: ")
  client_socket.connect((server_host, 8080))

  # Exchange names
  name = input("Enter your name: ")
  client_socket.send(name.encode())
  server_name = client_socket.recv(1024).decode()
  print(f"Connected to {server_name}")

  # Exchange public keys
  client_socket.send(client_public_key.export_key())
  server_pub_key = RSA.import_key(client_socket.recv(2048))
  
  return client_socket, server_pub_key, client_private_key

def send_message(client_socket, server_pub_key, client_private_key):
  global client_active
  while client_active:
    try:
      message = input("> ")
      if message.lower() == 'exit':
        client_active = False
        break

      # Sign message
      h = SHA256.new(message.encode())
      signature = pkcs1_15.new(client_private_key).sign(h)
      signed_data = message.encode() + signature

      # Encrypt with AES
      session_key = get_random_bytes(16)
      cipher_aes = AES.new(session_key, AES.MODE_EAX)
      nonce = cipher_aes.nonce
      ciphertext, tag = cipher_aes.encrypt_and_digest(signed_data)

      # Encrypt session key
      cipher_rsa = PKCS1_OAEP.new(server_pub_key)
      encrypted_session_key = cipher_rsa.encrypt(session_key)

      # Send data
      data = encrypted_session_key + nonce + tag + ciphertext
      client_socket.send(len(data).to_bytes(4, 'big') + data)
    except Exception as e:
      print(f"Send error: {e}")
      client_active = False
      break

  print("Closing connection...")
  try:
    client_socket.close()
  except:
    pass

def receive_messages(client_socket):
  global client_active
  while client_active:
    try:
      # Read message length
      length_bytes = client_socket.recv(4)
      if not length_bytes:
        client_active = False
        break
      length = int.from_bytes(length_bytes, 'big')
      encrypted_data = client_socket.recv(length)
      if not encrypted_data:
        client_active = False
        break

      # Split components
      encrypted_session_key = encrypted_data[:256]
      nonce = encrypted_data[256:272]
      tag = encrypted_data[272:288]
      ciphertext = encrypted_data[288:]

      # Decrypt session key
      cipher_rsa = PKCS1_OAEP.new(client_private_key)
      session_key = cipher_rsa.decrypt(encrypted_session_key)

      # Decrypt message
      cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
      decrypted_data = cipher_aes.decrypt_and_verify(ciphertext, tag)

      # Print message
      print(f"\n{decrypted_data.decode()}\n> ", end='')
    except (ConnectionResetError, BrokenPipeError):
      print("\nConnection closed by server")
      client_active = False
      break
    except Exception as e:
      print(f"\nReceive error: {e}")
      client_active = False
      break

def client_shutdown():
  global client_active
  client_active = False
  print("\nClient shut down gracefully")
  os._exit(0)

def main():
  global client_private_key
  try:
    client_socket, server_pub_key, client_private_key = connect_to_server()
    
    # Start receive thread
    receive_thread = threading.Thread(target=receive_messages, args=(client_socket,))
    receive_thread.start()

    # Start send thread
    send_thread = threading.Thread(target=send_message, args=(client_socket, server_pub_key, client_private_key))
    send_thread.start()

    # Wait for threads to finish
    receive_thread.join()
    send_thread.join()

  except KeyboardInterrupt:
    client_shutdown()
  except Exception as e:
    print(f"Connection error: {e}")
    client_shutdown()

if __name__ == '__main__':
  main()