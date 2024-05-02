import socket

def main():
    item_data = ""
    with open("items.txt", "r") as file:
        item_data = file.read()
    
    # Get the hostname of the machine running the script
    hostname = socket.gethostname()
    server_ip = socket.gethostbyname(hostname)
    print(server_ip)
    
    # Define the port number
    server_port = 12346  # Default port number

    # Create a socket and bind it to the server IP and port
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((server_ip, server_port))
    server_socket.listen(1)
    print("Server is listening...")
    
    while True:
        conn, addr = server_socket.accept()
        with conn:
            print('Connected by', addr)
            conn.sendall(item_data.encode())

if __name__ == "__main__":
    main()
