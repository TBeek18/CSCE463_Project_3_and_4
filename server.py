import socket
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import os

# Server state
shutdown_flag = False
clients = []
server_socket = None

def handle_client(conn, addr):
  global clients
  client_name = None
  client_pub_key = None
  try:
    # Exchange names
    client_name = conn.recv(1024).decode()
    conn.send("Server".encode())
    print(f"Client {client_name} ({addr}) connected")

    # Exchange public keys
    client_pub_key = RSA.import_key(conn.recv(2048))
    conn.send(open('server_public.pem', 'rb').read())
    clients.append((conn, client_pub_key, client_name))

    while not shutdown_flag:
      try:
        # Receive message length
        length_bytes = conn.recv(4)
        if not length_bytes:
          break
        length = int.from_bytes(length_bytes, 'big')
        encrypted_data = conn.recv(length)

        # Split into components
        encrypted_aes_key = encrypted_data[:256]
        nonce = encrypted_data[256:272]
        tag = encrypted_data[272:288]
        ciphertext = encrypted_data[288:]

        # Decrypt AES key
        cipher_rsa = PKCS1_OAEP.new(server_private_key)
        aes_key = cipher_rsa.decrypt(encrypted_aes_key)

        # Decrypt message
        cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
        decrypted_data = cipher_aes.decrypt_and_verify(ciphertext, tag)

        # Extract message and signature
        message = decrypted_data[:-256]
        signature = decrypted_data[-256:]

        # Verify signature
        h = SHA256.new(message)
        try:
          pkcs1_15.new(client_pub_key).verify(h, signature)
          formatted_msg = f"{client_name}: {message.decode()}"
          print(f"[Valid] {formatted_msg}")
          # Broadcast with sender's name
          for client in clients:
            if client[0] != conn:
              send_encrypted(formatted_msg.encode(), client[0], client[1])
        except (ValueError, TypeError):
          print(f"[Invalid Signature] from {client_name}")

      except (ConnectionResetError, BrokenPipeError):
        break

  except Exception as e:
    print(f"Client {addr} error: {e}")
  finally:
    if client_name:
      print(f"{client_name} disconnected")
    if (conn, client_pub_key, client_name) in clients:
      clients.remove((conn, client_pub_key, client_name))
    conn.close()

def send_encrypted(message, recipient_conn, recipient_pub_key):
  try:
    # Generate session key
    session_key = get_random_bytes(16)
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    nonce = cipher_aes.nonce
    ciphertext, tag = cipher_aes.encrypt_and_digest(message)

    # Encrypt session key
    cipher_rsa = PKCS1_OAEP.new(recipient_pub_key)
    encrypted_session_key = cipher_rsa.encrypt(session_key)

    # Send data
    data = encrypted_session_key + nonce + tag + ciphertext
    recipient_conn.send(len(data).to_bytes(4, 'big') + data)
  except Exception as e:
    print(f"Broadcast error: {e}")

def server_shutdown():
  global shutdown_flag, server_socket
  shutdown_flag = True
  
  # Close all client connections
  for client in clients[:]:
    try:
      client[0].close()
    except:
      pass
  
  # Close server socket
  if server_socket:
    try:
      server_socket.close()
    except:
      pass
  
  print("\nServer shut down gracefully")
  os._exit(0)

def main():
  global server_socket, server_private_key

  # Generate server keys if not present
  if not os.path.exists('server_private.pem') or not os.path.exists('server_public.pem'):
    key = RSA.generate(2048)
    with open('server_private.pem', 'wb') as f:
      f.write(key.export_key())
    with open('server_public.pem', 'wb') as f:
      f.write(key.publickey().export_key())

  server_private_key = RSA.import_key(open('server_private.pem', 'rb').read())

  server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  server_socket.bind(('0.0.0.0', 8080))
  server_socket.listen()
  print("Server listening on port 8080 (type 'shutdown' to quit)")

  # Start shutdown handler thread
  def shutdown_listener():
    while True:
      cmd = input()
      if cmd.lower() == "shutdown":
        server_shutdown()

  threading.Thread(target=shutdown_listener, daemon=True).start()

  # Main accept loop
  while not shutdown_flag:
    try:
      conn, addr = server_socket.accept()
      thread = threading.Thread(target=handle_client, args=(conn, addr))
      thread.start()
    except OSError:
      break  # Socket closed during shutdown

if __name__ == '__main__':
  try:
    main()
  except KeyboardInterrupt:
    server_shutdown()