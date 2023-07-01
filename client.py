import socket
from server import Server
from entities import Chat, Message
from utils import sha3_256_hash, check_password_strength, create_e2e_message, read_e2e_message, send, receive
from random import randint
from elgamal import elgamal_generate_key, ElgamalKey
from rsa import client_rsa_keys

BUFFSIZE = 1024
MESSAGE_SIZE = 175

class Client:
    def __init__(self):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.username = ""
        self.password = ""
        self.elgamal_key = elgamal_generate_key()

    def up(self):
        self.sock.connect((Server.IP, Server.PORT))
        App(self).run_app()


class App:
    def __init__(self, client):
        self.client = client
        self.chats = {}
        self.sequence_numbers = {}
        self.elgamal_keys = {}
        
        print(self.client.username)
        self.send_parameters = 'public_key.pem', f'private_key_{self.client.username}.pem', self.client.password
        self.receive_parameters = f'private_key_{self.client.username}.pem', 'public_key.pem', self.client.password

        self.APP_MENU_OPTIONS = ["See inbox", "See online users", "Send a message", "Create new group", "Add group member", "Remove group member", "See chat", "Quit"]
        self.APP_MENU_FUNCTIONS = [self.see_inbox_menu, self.see_online_users, self.send_message_menu, self.create_new_group, self.add_group_member, self.remove_group_member]

    def run_app(self):
        while True:
            if self.show_auth_menu(): break

        while True:
            quitted = self.show_app_menu()
            if quitted: break

    def show_auth_menu(self):
        print("Please login or create a new account")
        print("1. Login")
        print("2. Register")

        input_option = int(input())
        if input_option == 2:
            self.client.sock.send("2".encode())
            return self.register() and self.login()
        if input_option == 1:
            self.client.sock.send("1".encode())
            return self.login()
        
        return False

    def show_app_menu(self):
        print("Please select what you want to do from the menu below")
        for i in range(1, len(self.APP_MENU_OPTIONS) + 1):
            print(f"{i}. {self.APP_MENU_OPTIONS[i - 1]}")

        input_option = int(input())
        if input_option == len(self.APP_MENU_OPTIONS): # Quit
            return True
        
        if input_option == len(self.APP_MENU_OPTIONS) - 1: # See chat
            self.see_chat_menu()
            return False
        
        send(f"{input_option}", self.client.sock, self.send_parameters)
        self.APP_MENU_FUNCTIONS[input_option - 1]()
        return False

    def see_inbox_menu(self):
        self.update_unread_messages()
        for username, chat in self.chats.items():
            print(f"{username} [{chat.unread_message_count}]" if chat.unread_message_count else username)

    def update_unread_messages(self):
        new_chat_count = int(receive(self.client.sock, self.receive_parameters))
        send("ACK", self.client.sock, self.send_parameters)
        for _ in range(new_chat_count):
            username = receive(self.client.sock, self.receive_parameters)
            send("ACK", self.client.sock, self.send_parameters)
            if username not in self.chats: self.chats[username] = Chat(username)
            new_messages = int(receive(self.client.sock, self.receive_parameters))
            send("ACK", self.client.sock, self.send_parameters)
            for _ in range(new_messages):
                sender = receive(self.client.sock, self.receive_parameters)
                send("ACK", self.client.sock, self.send_parameters)
                C1 = receive(self.client.sock, self.receive_parameters)
                send("ACK", self.client.sock, self.send_parameters)
                C2 = receive(self.client.sock, self.receive_parameters)
                send("ACK", self.client.sock, self.send_parameters)
                sequence_number, message = read_e2e_message(username, self.sequence_numbers, C1, C2, self.client.elgamal_key)
                if sequence_number: 
                    self.chats[username].unread_message_count += 1
                    self.sequence_numbers[username] += 1
                    self.chats[username].messages.append(Message(sender, message))

    def see_chat_menu(self):
        print("Please enter the chat you want to see:")
        username = input()
        self.show_chat(username)

    def show_chat(self, username):
        if username not in self.chats:
            print("Username does not exist in chats")
            return
        
        unread_message_count = self.chats[username].unread_message_count
        if unread_message_count == 0:
            print('\n'.join([f"{m.sender}: {m.text}" for m in self.chats[username].messages]))
        else:
            print('\n'.join([f"{m.sender}: {m.text}" for m in self.chats[username].messages[:-unread_message_count]]))
            print('-'*50)
            print('\n'.join([f"{m.sender}: {m.text}" for m in self.chats[username].messages[-unread_message_count:]]))

        self.chats[username].unread_message_count = 0

    def see_online_users(self):
        online_users = receive(self.client.sock, self.receive_parameters)
        print(online_users)

    def send_message_menu(self):
        self.update_unread_messages()

        print("Please enter the chat you want to send a message to:")
        username = input()
        send(username, self.client.sock, self.send_parameters)
        response = receive(self.client.sock, self.receive_parameters)
        if response != "User Found" and response != "Group Found":
            print(response)
            return
        
        if username not in self.sequence_numbers: self.sequence_numbers[username] = randint(1, 1e6)

        print("Please enter your message:")
        message = input()

        if response == "User Found":
            self.send_message_to_user(username, message, self.sequence_numbers[username])
        else:
            self.send_message_to_group(username, message, self.sequence_numbers[username])
        
        self.sequence_numbers[username] += 1
        if username not in self.chats: self.chats[username] = Chat(username)
        self.chats[username].messages.append(Message(self.client.username, message))
        
    def send_message_to_user(self, username, message, sequence_number):
        self.resolve_elgamal_key(username)

        C1, C2 = create_e2e_message(message, sequence_number, self.elgamal_keys[username])
        send(C1, self.client.sock, self.send_parameters)
        receive(self.client.sock, self.receive_parameters)    # ACK
        send(C2, self.client.sock, self.send_parameters)
        receive(self.client.sock, self.receive_parameters)    # ACK

    def send_message_to_group(self, username, message, sequence_number):
        user_count = int(receive(self.client.sock, self.receive_parameters))
        send("ACK", self.client.sock, self.send_parameters)   # ACK

        for _ in range(user_count):
            username = receive(self.client.sock, self.receive_parameters)
            send("ACK", self.client.sock, self.send_parameters)   # ACK

            self.send_message_to_user(username, message, sequence_number)

    def resolve_elgamal_key(self, username):
        if username not in self.elgamal_keys:
            send("Get Key", self.client.sock, self.send_parameters)
            q = int(receive(self.client.sock, self.receive_parameters))
            send("ACK", self.client.sock, self.send_parameters)   # ACK
            α = int(receive(self.client.sock, self.receive_parameters))
            send("ACK", self.client.sock, self.send_parameters)   # ACK
            Y = int(receive(self.client.sock, self.receive_parameters))
            self.elgamal_keys[username] = ElgamalKey(q, α, Y)
        else:
            send("OK", self.client.sock, self.send_parameters)

        return True

    def register(self):
        print("Please pick a username:")
        self.client.username = input()
        self.client.sock.send(self.client.username.encode())

        response = self.client.sock.recv(BUFFSIZE).decode()
        if response != "OK":
            print(response)
            return False
        
        self.client.password = sha3_256_hash(self.select_password())

        # define public and private keys of the this clients
        client_rsa_keys(username=self.client.username, password=self.client.password)
        
        print("here")

        send(self.client.password, self.client.sock, ('public_key.pem', f'private_key_{self.client.username}.pem', self.client.password))
        print("ho")
        receive(self.client.sock, (f'private_key_{self.client.username}.pem', 'public_key.pem', self.client.password))   # ACK
        
        print("here")

        (q, α, Y), _ = self.client.elgamal_key.unpack()
        send(str(q), self.client.sock, ('public_key.pem', f'private_key_{self.client.username}.pem', self.client.password))
        receive(self.client.sock, (f'private_key_{self.client.username}.pem', 'public_key.pem', self.client.password))   # ACK
        send(str(α), self.client.sock, ('public_key.pem', f'private_key_{self.client.username}.pem', self.client.password))
        receive(self.client.sock, (f'private_key_{self.client.username}.pem', 'public_key.pem', self.client.password))   # ACK
        send(str(Y), self.client.sock, ('public_key.pem', f'private_key_{self.client.username}.pem', self.client.password))
        receive(self.client.sock, (f'private_key_{self.client.username}.pem', 'public_key.pem', self.client.password))   # ACK
        
        print("here")
        
        return True


    def select_password(self):
        print("Please pick a password:")
        while True:
            password = input()
            if check_password_strength(password): return password
            print("The password must be at least 8 charachters and contain at least one uppercase letter,")
            print("one lowercase letter, one digit, and one special charachter!")


    def login(self):
        print("Please enter your username:")
        self.client.username = input()
        send(self.client.username, self.client.sock, self.send_parameters)
        
        print("Please enter your password:")
        hashed_password = sha3_256_hash(input())
        send(hashed_password, self.client.sock, self.send_parameters)

        response = receive(self.client.sock, self.receive_parameters)
        if response == "OK": return True
        else:
            print(response)
            return False

    def create_new_group(self):
        print("Please enter the name of the group:")
        username = input()
        send(username, self.client.sock, self.send_parameters)
        response = receive(self.client.sock, self.receive_parameters)
        if response != "OK":
            print(response)
            return
        
        self.send_group_members()

    def send_group_members(self):
        print("How many members you want to add now?")
        member_count = int(input())
        send(f"{member_count}", self.client.sock, self.send_parameters)
        for _ in range(member_count):
            print("Please enter the next username to add")
            username = input()
            send(username, self.client.sock, self.send_parameters)
            response = receive(self.client.sock, self.receive_parameters)
            print(response)

    def add_group_member(self):
        print("Please enter the group name")
        username = input()
        send(username, self.client.sock, self.send_parameters)
        response = receive(self.client.sock, self.receive_parameters)
        if response != "OK":
            print(response)
            return
        print("Please enter the username to add")
        user = input()
        send(user, self.client.sock, self.send_parameters)
        response = receive(self.client.sock, self.receive_parameters)
        print(response)

    def remove_group_member(self):
        print("Please enter the group name")
        username = input()
        send(username, self.client.sock, self.send_parameters)
        response = receive(self.client.sock, self.receive_parameters)
        if response != "OK":
            print(response)
            return
        print("Please enter the username to remove")
        user = input()
        send(user, self.client.sock, self.send_parameters)
        response = receive(self.client.sock, self.receive_parameters)
        print(response)


if __name__ == "__main__":
    Client().up()
