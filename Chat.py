import socket
import json
import base64
import time
import zlib
import hmac
import hashlib
import threading
from datetime import datetime
from Cryptodome.Random import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from Cryptodome import Random

# CHAP status: 
# 0 - not initialised 
# 1 - sent hello
# 2 - received hello
# 3 - sent challenge1
# 4 - received challenge1
# 5 - sent response1
# 6 - received response1
# 7 - sent chap ack
# 8 - received chap ack
# 9 (2) - sent challenge2 
# 10 (3) - received challenge2
# 11 (4) - sent response2
# 12 - received response2
# 13 - sent chap ack
# 14 - received chap ack
# 15 - done CHAPing 

chap_status = 0
ack_status = False
ack_type = False
chap_pass = None
validated = 0
dest_user = None
dest_pass = None
start = False
dest_pas = None
password = None
dskey = None

 
class PDU:
    def __init__(self, msg_type, body, crc=None, timestamp = None, hash=None, encryption_value=None):
        self.header = {'msg_type': msg_type, 'crc': crc, 'timestamp': None}
        self.body = body
        self.security = {'hmac': {'type': 'SHA256', 'hash': hash},
                 'encryption': encryption_value}
        if timestamp:
            self.header['timestamp'] = timestamp
        else:
            self.header['timestamp'] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        if body:
            self.body = body
            self.security['encryption'] = 'AES256_CBC'
        else:
            self.body = None
            self.security['encryption'] = None
            
    def get_body(self):
        return self.body
    
    def set_body(self, new_body):
        self.body = new_body
 
    def set_crc(self):
        crc = zlib.crc32(json.dumps(self.__dict__).encode())
        self.header['crc'] = crc

    def is_valid(self, password):
        hash1 = self.security['hmac']['hash']
        crc1 = self.header['crc']
        self.security['hmac']['hash'] = None
        self.header['crc'] = None
        crc = zlib.crc32(json.dumps(self.__dict__).encode()) 
        self.header['crc'] = crc1
        msg = json.dumps(self.__dict__).encode()  
        hmac_value = hmac.new(password.encode(), msg, digestmod=hashlib.sha256).hexdigest()
        return crc == crc1 and hmac_value == hash1

    def compute_hmac(self, password):
        self.security['hmac']['hash'] = None
        msg = json.dumps(self.__dict__).encode()
        hmac_value = hmac.new(password.encode(), msg, digestmod=hashlib.sha256).hexdigest()
        self.security['hmac']['hash'] = hmac_value

    def encrypt_body(self, password):
        global dskey
        if self.body:
            encr_obj = DHSKEncryption(user_secret=password, key=dskey)
            self.body = encr_obj.encrypt(plaintext=self.body)
            self.body = base64.b64encode(self.body).decode()
            
    def decrypt_body(self, password):
        if self.body:
            decr_obj = DHSKEncryption(user_secret=password, key=dskey)
            print(self.body)
            self.body = self.body.encode()
            self.body = base64.b64decode(self.body)
            print(self.body)
            self.body = decr_obj.decrypt(ciphertext=self.body)
          
chap_var = PDU("", None)

class DHSKEncryption:
    def __init__(self, user_secret: str, key):
        self.user_secret = user_secret.encode()
        self.IV = Random.get_random_bytes(16)
        self.key = key

    def encrypt(self, plaintext: str) -> bytes:
        aes = Cipher(algorithms.AES(self.key), modes.CBC(self.IV), backend=default_backend())
        encryptor = aes.encryptor()
        padded_plaintext = self._pad(plaintext.encode())
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        return self.IV + ciphertext

    def decrypt(self, ciphertext: bytes) -> str:
        IV = ciphertext[:16]
        ciphertext = ciphertext[16:]
        aes = Cipher(algorithms.AES(self.key), modes.CBC(IV), backend=default_backend())
        decryptor = aes.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        plaintext = self._unpad(padded_plaintext)
        return plaintext.decode()

    @staticmethod
    def _pad(data: bytes) -> bytes:
        pad_length = 16 - (len(data) % 16)
        return data + bytes([pad_length] * pad_length)

    @staticmethod
    def _unpad(data: bytes) -> bytes:
        pad_length = data[-1]
        return data[:-pad_length]
            
class DiffieHellman:
    def __init__(self):
        # Generate Diffie-Hellman parameters
        p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
        g = 2
        self.dh_parameters = dh.DHParameterNumbers(p, g).parameters(default_backend())
        
        # Generate the private key
        self.private_key = self.dh_parameters.generate_private_key()

        # Generate the public key
        self.public_key = self.private_key.public_key()

    def exchange_public_key(self, ssocket):
        # Serialize the public key
        serialized_public_key = self.public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                              format=serialization.PublicFormat.SubjectPublicKeyInfo)

         # Send the public key over the socket
        ssocket.sendall(serialized_public_key)
        
    def load_peer_public_key(self, rsocket):
        # Receive the peer's public key from the socket
        data = rsocket.recv(1024)
        if data:
            peer_public_key_bytes = data
            self.peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes, backend=default_backend())

    def generate_shared_key(self):
        # Compute the shared secret key
        self.shared_secret = self.private_key.exchange(self.peer_public_key)

        # Derive a key from the shared secret key
        salt = b'salt'
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256, length=32, salt=salt, iterations=100000, backend=default_backend())
        self.key = kdf.derive(self.shared_secret)
        return self.key
    
dh_object = DiffieHellman()

class UserInput:
    def load_users(filename):
        with open(filename) as f:
            data = json.load(f)
        return data

    def search_user(username, userfile):
        for user in userfile:
            if user['username'] == username:
                return user['password'], user['port'], user['ip']
        return None

    def check_password(username, password, userfile):
        for user in userfile:
            if user['username'] == username and user['password'] == password:
                return True
        return False

    def get_input(end_char):
        user_input = ""
        while True:
            char = input()
            if not char:
                break
            user_input += char
        return user_input

    def slect_mode(userfile):
        mode = int(input("Enter 1 to select the destination user from the user file or 2 to enter the data manually: "))
        if mode == 1:
            user = input("Enter the user you want to send a message to: ")
            pas, dest_port, dest_ip = UserInput.search_user(user, userfile)
        else:
            dest_ip = input("Enter destination IP address: ")
            dest_port = int(input("Enter destination port: "))
        return pas, dest_port, dest_ip

class ACK:
    def send_ack(password, socket):
        ack_pdu = PDU('ack', None)
        ack_pdu.encrypt_body(password)
        ack_pdu.set_crc()
        ack_pdu.compute_hmac(password)
        socket.sendall(json.dumps(ack_pdu.__dict__).encode('utf-8'))
        print("Message received, sent ACK")

    def send_nack(password, socket):
        nack_pdu = PDU('nack', None)
        nack_pdu.encrypt_body(password)
        nack_pdu.set_crc()
        nack_pdu.compute_hmac(password)
        socket.sendall(json.dumps(nack_pdu.__dict__).encode('utf-8'))
        print("Invalid message received, sent NACK")

class CHAP:
    def send_hello(username, password, socket):
        pdu = PDU('hello', username)
        pdu.encrypt_body(password)
        pdu.set_crc()
        pdu.compute_hmac(password)
        socket.sendall(json.dumps(pdu.__dict__).encode())
        print("Sent hello message.")

    def send_chap(password, socket):
        challenge = str(random.getrandbits(256))
        pdu = PDU("challenge", challenge)
        pdu.encrypt_body(password)
        pdu.set_crc()
        pdu.compute_hmac(password)
        socket.sendall(json.dumps(pdu.__dict__).encode())
        print("Sent CHAP challenge.")
        return challenge

    def respond_chap(pdu1, password, socket):
        challenge = pdu1.get_body()
        response = hmac.new(password.encode(), challenge.encode(), digestmod=hashlib.sha256).hexdigest()
        pdu = PDU("response", response)
        pdu.encrypt_body(password)
        pdu.set_crc()
        pdu.compute_hmac(password)
        socket.sendall(json.dumps(pdu.__dict__).encode())
        print("Sent CHAP response.")

    def check_chap(pdu, password, challenge):
        received_response = pdu.get_body()
        expected_response = hmac.new(password.encode(), challenge.encode(), digestmod=hashlib.sha256).hexdigest()
        if received_response == expected_response:
            print("CHAP validated.")
            return True
        else:
            return False

    def send_ack(password, socket):
        chap_ack_pdu = PDU('chapack', None)
        chap_ack_pdu.encrypt_body(password)
        chap_ack_pdu.set_crc()
        chap_ack_pdu.compute_hmac(password)
        socket.sendall(json.dumps(chap_ack_pdu.__dict__).encode())
        print("Sent CHAP ACK")

    def send_nack(password, socket):
        chap_nack_pdu = PDU('chapnack', None)
        chap_nack_pdu.encrypt_body(password)
        chap_nack_pdu.set_crc()
        chap_nack_pdu.compute_hmac(password)
        socket.sendall(json.dumps(chap_nack_pdu.__dict__).encode())
        print("Sent CHAP NACK")
        
class ASyncChatApp:

    def run_send_thread(self, ssocket, user, pas1):

        global ack_status
        global ack_type
        global chap_status
        global chap_var
        global chap_pass
        global validated
        global dest_user
        global start
        run = True
        global dh_object
        dh_object.exchange_public_key(ssocket)
            
        while run:
            if validated == 2:
                print("Mutual CHAP validation done.")
                validated = 3
                chap_status = 7
            elif validated == 3:
                print("Enter the message to send and when you want to send it press the enter key twice: ")
                message = UserInput.get_input('\n')

                pdu = PDU('text', message)
                pdu.encrypt_body(pas1)
                pdu.set_crc()
                pdu.compute_hmac(pas1)

                print("Sender: " + message)

                if message.strip() == "close_con":
                    print("Sender exiting...")
                    ssocket.shutdown(socket.SHUT_RDWR)
                    ssocket.close()
                    run = False
                    break
                #print("Waiting for receiver response...")

                ssocket.sendall(json.dumps(pdu.__dict__).encode()) 
            else:
                time.sleep(0.5)
                if chap_status == 0 and start:
                    CHAP.send_hello(user, pas1, ssocket)
                    chap_status = 1
                elif chap_status == 2:
                    chall_sent = CHAP.send_chap(pas1, ssocket)
                    chap_status = 3
                elif chap_status == 4:
                    CHAP.respond_chap(chap_var, pas1, ssocket)
                    chap_status = 5
                elif chap_status == 6:
                    if CHAP.check_chap(chap_var, pas1, chall_sent) == True:
                        CHAP.send_ack(pas1, ssocket)
                        validated += 1
                        if validated == 2:
                            chap_status = 7
                    else:
                        CHAP.send_nack(pas1, ssocket)
                        ("Wrong CHAP response received, CHAP failed.")
                        ssocket.shutdown(socket.SHUT_RDWR)
                        ssocket.close()
                        run = False
        
            if ack_status == True :
                if ack_type == False:
                    ACK.send_nack(pas1,ssocket)
                else:
                    ACK.send_ack(pas1, ssocket)
            else:
                continue
            
    def run_receive_thread(self, rs, user, pas):
        rsocket, caddress = rs.accept()
        nack_count = 0
        run = True
        THRESHOLD = 250
        CC_MESAGE = "Closing connection with the client."
        global ack_status
        global ack_type
        global chap_status
        global chap_var
        global validated
        global start
        global dskey
        global dh_object
        dh_object.load_peer_public_key(rsocket)
        dskey = dh_object.generate_shared_key()
        while run:
            time.sleep(0.5)
            ack_type = False
            ack_status = False  
            while nack_count < 3:
                try:
                    data = rsocket.recv(1024)
                    #print("Received packet:", data)
                    if data:
                        try:
                            pdu = json.loads(data.decode())
                            pdu_object = PDU(pdu['header']['msg_type'], pdu['body'], pdu['header']['crc'], pdu['header']['timestamp'], pdu['security']['hmac']['hash'])
                            received_time = datetime.strptime(pdu['header']['timestamp'], '%Y-%m-%d %H:%M:%S')
                            difference = datetime.utcnow() - received_time
                            if difference.total_seconds() > THRESHOLD:
                                print("Message received outside the threshold window.")
                                print(CC_MESAGE)
                                rsocket.shutdown(socket.SHUT_RDWR)
                                rsocket.close()
                                run = False
                                break
                            else:
                                if pdu_object.is_valid(pas):
                                    pdu_object.decrypt_body(pas)
                                    if pdu['header']['msg_type'] == 'text':
                                        text = pdu_object.get_body()
                                        text = text.strip()
                                        print(user + ": " + text)
                                        if text == "close_con":
                                            print(CC_MESAGE)
                                            rsocket.shutdown(socket.SHUT_RDWR)
                                            rsocket.close()
                                            run  = False
                                            break
                                        else:
                                            ack_status = True
                                            ack_type = True
                                    elif pdu['header']['msg_type'] == 'hello':
                                        print("Received CHAP hello.")
                                        chap_status = 2
                                    elif pdu['header']['msg_type'] == 'challenge':
                                        print("Received CHAP challenge.")
                                        chap_var = pdu_object
                                        chap_status = 4
                                    elif pdu['header']['msg_type'] == 'response':
                                        print("Received CHAP response.")
                                        chap_var = pdu_object
                                        chap_status = 6
                                    elif pdu['header']['msg_type'] == 'chapack':
                                        print("CHAP ACK received.")
                                        chap_status = 2
                                        validated += 1
                                        if validated == 2:
                                            chap_status = 7
                                    elif pdu['header']['msg_type'] == 'chapnack':
                                        print("CHAP NACK received, CHAP failed.")
                                    elif pdu['header']['msg_type'] == 'ack':
                                        #print("ACK received, message sent successfully.")
                                        continue
                                    elif pdu['header']['msg_type'] == 'nack':
                                        print("NACK received, message not sent.")
                                        continue
                                    else:
                                        ack_status = True
                                        ack_type = False
                                        nack_count += 1
                                else:
                                    ack_status = True
                                    ack_type = False
                                    nack_count += 1
                        except json.decoder.JSONDecodeError as e:
                            print("Error decoding JSON: ", e)
                    else:
                        print("Client disconnected.")
                        print(CC_MESAGE)
                        rsocket.shutdown(socket.SHUT_RDWR)
                        rsocket.close()
                        run = False
                        break
                except socket.error as e:
                    print("Error receiving data:", e)
                    print(CC_MESAGE)
                    rsocket.shutdown(socket.SHUT_RDWR)
                    rsocket.close()
                    run = False
                    break
            if nack_count == 3:
                run = False
                break
            
            
    def main(self):
        print("Running ASyncChatApp")

        global chap_pass
        global start
        global password
        global dest_pas

        filename = input("Enter the filename: ").strip()
        user_file = UserInput.load_users(filename)
        username = input("Enter your username: ").strip()
        password = input("Enter your password: ").strip()
        if(UserInput.check_password(username, password, user_file)):
            print("You have successfully logged in!")
            port = int(input("Enter a port to act for incomming connections: "))
            rs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            rs.bind(("", port))
            rs.listen(1)

            mode = int(input("Enter 1 to select the destination user from the user file or 2 to enter the data manually: "))
            if mode == 1:
                dest_user = input("Enter the user you want to send a message to: ").strip()
                dest_pas, dest_port, dest_ip = UserInput.search_user(dest_user, user_file)
                chap_pass = dest_pas
            else:
                dest_ip = input("Enter destination IP address: ").strip()
                dest_port = int(input("Enter destination port: "))
            
            if input("Do you want to initialize the communication?") == "yes":
                start = True
            else:
                start = False

            ss = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ss.connect((dest_ip, dest_port))
            print("Connected to receiver. Type 'close_conn' to exit.")

            send_thread = threading.Thread(target=self.run_send_thread, args=(ss, username, password))
            receive_thread = threading.Thread(target=self.run_receive_thread, args=(rs, dest_user, dest_pas))

            send_thread.start()
            receive_thread.start()

            send_thread.join()
            receive_thread.join()
        else:
            print("Wrong credentials!")

if __name__ == '__main__':
    ASyncChatApp().main()