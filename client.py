from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import socket

# Generate RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

# Serialize public key
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Deserialize public key
public_key = serialization.load_pem_public_key(public_key_pem)

def encrypt_message(message, public_key):
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def main():
    try:
        # Define the IP address and port number of the server
        server_ip = "128.226.114.206"  # Update this with the correct IP address
        server_port = 12346  # Default port number

        # Create a socket and connect it to the server IP and port
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.connect((server_ip, server_port))
        
        item_data = server_socket.recv(1024).decode()
        print("Received item data from server:", item_data)
        
        item_number = input("Enter the item number you wish to purchase: ")
        name = input("Enter your name: ")
        credit_card_number = input("Enter your credit card number: ")
        
        # Sign the message
        signature = private_key.sign(
            (item_number + name + credit_card_number).encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Concatenate data and signature
        message = "||".join([item_number, name, credit_card_number, signature.hex()])
        
        # Encrypt and send message to server
        encrypted_message = encrypt_message(message, public_key)
        server_socket.sendall(encrypted_message)
        
        response = server_socket.recv(1024).decode()
        if response == "1":
            print("Your order is confirmed.")
        else:
            print("Credit card transaction is unauthorized.")
        
        server_socket.close()
    except Exception as e:
        print("An error occurred during execution:", e)

if __name__ == "__main__":
    main()
