#%%
import socket
from _thread import start_new_thread
from DiffieHellman import generate_secret, diffie_hellman_public, diffie_hellman_key
from RC4 import RC4
from SDES import SDES, SDES_Decode

key = None
cipher = None
ciphers = {'rc4': RC4, 'sdes': SDES}
clients = []
server = None
waiting_answer_client = None
source_secret = None
prime = 353
alfa = 3

def listen_client(client, addr):
    print(addr[0], 'connected!')
    clients.append([addr[0], client])
    while clients:
        try:
            result = client.recv(2048)
            if waiting_answer_client:
                answer_client(result)
            else:
                show_msg(addr[0], result, client)
        except:
            pass

def listen_server():
    while server:
        try:
            conn, addr = server.accept()
            start_new_thread(listen_client, (conn, addr))
        except:
            pass

def list_clients():
    for c in clients:
        print(c[0])

def stop_server():
    global key, cipher, clients, server
    key = None
    cipher = None
    for client in clients:
        client[1].close()
    clients = []
    if server:
        server.close()
        server = None

def start_server(ip, port):
    global server
    stop_server()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((ip, port))
    server.listen(100)
    start_new_thread(listen_server, ())

def answer_client(result):
    global key, source_secret, waiting_answer_client
    source_secret = generate_secret(prime)
    key = str(diffie_hellman_key(prime, source_secret, int.from_bytes(result, byteorder='big')))
    waiting_answer_client.send(diffie_hellman_public(prime, alfa, source_secret).to_bytes(10, byteorder='big'))
    waiting_answer_client = None

def command_check(text):
    global key, cipher
    if text[:6] == '\\crypt':
        cipher = ciphers.get(text[7:])
        if not cipher:
            key = None
        return True
    return False

def show_msg(ip, text, client):
    global key, source_secret
    text = str(text, 'utf-8')
    is_command = command_check(text)
    if not is_command and cipher:
        if cipher == SDES:
            print(ip, ':', SDES_Decode(key, text))
        else:
            print(ip, ':', cipher(key, text))
    else:
        print(ip, ':', text)
    if is_command and cipher:
        source_secret = generate_secret(prime)
        client.send(diffie_hellman_public(prime, alfa, source_secret).to_bytes(10, byteorder='big'))
        key = str(diffie_hellman_key(prime, source_secret, int.from_bytes(client.recv(2048), byteorder='big')))

def send_msg(ip, text):
    global waiting_answer_client
    is_command = command_check(text)
    for client in clients:
        if client[0] == ip:
            try:
                if is_command and cipher:
                    waiting_answer_client = client[1]
                if not is_command and cipher:
                    client[1].send(cipher(key, text).encode())
                else:
                    client[1].send(bytes(text, 'utf-8'))
            except:
                pass
