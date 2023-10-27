import socket
import hashlib
from Crypto.Cipher import AES
from Crypto import Random

def generate_key(shared_secret):
    return hashlib.sha256(bytes([shared_secret])).digest()

def encrypt(message, key):
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    encrypted = iv + cipher.encrypt(message)
    return encrypted

def decrypt(encrypted, key):
    iv = encrypted[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CFB, iv)
    decrypted = cipher.decrypt(encrypted[AES.block_size:])
    return decrypted

def diffie_hellman_exchange(conn):
    p = 23
    g = 5
    
    private_key = Random.new().read(1)[0] % 256 
    public_key = (g ** private_key) % p 
    
    conn.send(bytes([public_key]))  
    
    other_public_key = ord(conn.recv(1))  
    shared_key = (other_public_key ** private_key) % p  
    
    return shared_key

def main():
    host = '127.0.0.1'
    port = 12345

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))

    shared_key = diffie_hellman_exchange(s)
    key = generate_key(shared_key)

    while True:
        message = input("Enter a message: ")
        encrypted_message = encrypt(message.encode(), key)
        s.send(encrypted_message)

        data = s.recv(1024)
        decrypted_data = decrypt(data, key)
        print("Received:", decrypted_data.decode())

    s.close()

if __name__ == '__main__':
    main()
