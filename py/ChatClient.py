#%%
import socket
from _thread import start_new_thread
from DiffieHellman import generate_secret, diffie_hellman_public, diffie_hellman_key
from RC4 import RC4
from SDES import SDES, SDES_Decode

key = None
cipher = None
ciphers = {'rc4': RC4, 'sdes': SDES}
server = None
waiting_answer_client = False
source_secret = None
prime = 353
alfa = 3

def listen_server():
    while server:
        try:
            result = server.recv(2048)
            if waiting_answer_client:
                answer_client(result)
            else:
                show_msg(result)
        except:
            pass

def stop_client():
    global key
    global cipher
    global server
    key = None
    cipher = None
    if server:
        server.close()
        server = None

def start_client(ip, port):
    global server
    stop_client()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.connect((ip, port))
    start_new_thread(listen_server, ())
    send_msg('\\crypt rc4')

def answer_client(result):
    global key
    global source_secret
    global waiting_answer_client
    source_secret = generate_secret(prime)
    key = str(diffie_hellman_key(prime, source_secret, int.from_bytes(result, byteorder='big')))
    server.send(diffie_hellman_public(prime, alfa, source_secret).to_bytes(10, byteorder='big'))
    waiting_answer_client = False

def command_check(text):
    global key
    global cipher
    if text[:6] == '\\crypt':
        cipher = ciphers.get(text[7:])
        if not cipher:
            key = None
        return True
    return False

def show_msg(text):
    global key
    global source_secret
    text = str(text, 'utf-8')
    is_command = command_check(text)
    if not is_command and cipher:
        if cipher == SDES:
            print('Server:', SDES_Decode(key, text))
        else:
            print('Server:', cipher(key, text))
    else:
        print('Server :', text)
    if is_command and cipher:
        source_secret = generate_secret(prime)
        server.send(diffie_hellman_public(prime, alfa, source_secret).to_bytes(10, byteorder='big'))
        key = str(diffie_hellman_key(prime, source_secret, int.from_bytes(server.recv(2048), byteorder='big')))

def send_msg(text):
    global waiting_answer_client
    try:
        is_command = command_check(text)
        if is_command and cipher:
            waiting_answer_client = True
        if not is_command and cipher:
            server.send(cipher(key, text).encode())
        else:
            server.send(bytes(text, 'utf-8'))
    except:
        pass
