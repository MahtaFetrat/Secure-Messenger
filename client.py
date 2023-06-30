import socket
from server import Server
from entities import Chat, Message
from utils import check_password_strength

BUFFSIZE = 1024

class Client:
    def __init__(self):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.username = ""
        self.password = ""

    def up(self):
        self.sock.connect((Server.IP, Server.PORT))
        App(self).run_app()


class App:
    def __init__(self, client):
        self.client = client
        self.chats = {}

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
        
        self.client.sock.send(f"{input_option}".encode())
        self.APP_MENU_FUNCTIONS[input_option - 1]()
        return False

    def see_inbox_menu(self):
        self.update_unread_messages()
        for username, chat in self.chats.items():
            print(f"{username} [{chat.unread_message_count}]" if chat.unread_message_count else username)

    def update_unread_messages(self):
        new_chat_count = int(self.client.sock.recv(BUFFSIZE).decode())
        for _ in range(new_chat_count):
            username = self.client.sock.recv(BUFFSIZE).decode()
            self.client.sock.send("ACK".encode())
            if username not in self.chats: self.chats[username] = Chat(username)
            new_messages = int(self.client.sock.recv(BUFFSIZE).decode())
            self.client.sock.send("ACK".encode())
            self.chats[username].unread_message_count += new_messages
            for _ in range(new_messages):
                sender = self.client.sock.recv(BUFFSIZE).decode()
                self.client.sock.send("ACK".encode())
                text = self.client.sock.recv(BUFFSIZE).decode()
                self.client.sock.send("ACK".encode())
                self.chats[username].messages.append(Message(sender, text))

    def see_chat_menu(self):
        print("Please enter the chat you want to see:")
        username = input()
        self.show_chat(username)

    def show_chat(self, username):
        unread_message_count = self.chats[username].unread_message_count if username in self.chats else 0
        if unread_message_count == 0:
            print('\n'.join([f"{m.sender}: {m.text}" for m in self.chats[username].messages]))
        else:
            print('\n'.join([f"{m.sender}: {m.text}" for m in self.chats[username].messages[:-unread_message_count]]))
            print('-'*50)
            print('\n'.join([f"{m.sender}: {m.text}" for m in self.chats[username].messages[-unread_message_count:]]))

        self.chats[username].unread_message_count = 0

    def see_online_users(self):
        online_users = self.client.sock.recv(BUFFSIZE).decode()
        print(online_users)

    def send_message_menu(self):
        print("Please enter the chat you want to send a message to:")
        username = input()
        self.client.sock.send(username.encode())
        response = self.client.sock.recv(BUFFSIZE).decode()
        if response != "OK":
            print(response)
            return
        
        print("Please enter your message:")
        message = input()
        self.client.sock.send(message.encode())

        if username not in self.chats: self.chats[username] = Chat(username)
        self.chats[username].messages.append(Message(self.client.username, message))

    def register(self):
        print("Please pick a username:")
        self.client.username = input()
        self.client.sock.send(self.client.username.encode())

        response = self.client.sock.recv(BUFFSIZE).decode()
        if response != "OK":
            print(response)
            return False
        
        self.client.password = self.select_password()
        self.client.sock.send(self.client.password.encode())
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
        self.client.sock.send(input().encode())
        
        print("Please enter your password:")
        self.client.sock.send(input().encode())

        response = self.client.sock.recv(BUFFSIZE).decode()
        if response == "OK": return True
        else:
            print(response)
            return False

    def create_new_group(self):
        print("Please enter the name of the group:")
        username = input()
        self.client.sock.send(username.encode())
        response = self.client.sock.recv(BUFFSIZE).decode()
        if response != "OK":
            print(response)
            return
        
        self.send_group_members()

    def send_group_members(self):
        print("How many members you want to add now?")
        member_count = int(input())
        self.client.sock.send(f"{member_count}".encode())
        for _ in range(member_count):
            print("Please enter the next username to add")
            username = input()
            self.client.sock.send(username.encode())
            response = self.client.sock.recv(BUFFSIZE).decode()
            print(response)

    def add_group_member(self):
        print("Please enter the group name")
        username = input()
        self.client.sock.send(username.encode())
        response = self.client.sock.recv(BUFFSIZE).decode()
        if response != "OK":
            print(response)
            return
        print("Please enter the username to add")
        user = input()
        self.client.sock.send(user.encode())
        response = self.client.sock.recv(BUFFSIZE).decode()
        print(response)

    def remove_group_member(self):
        print("Please enter the group name")
        username = input()
        self.client.sock.send(username.encode())
        response = self.client.sock.recv(BUFFSIZE).decode()
        if response != "OK":
            print(response)
            return
        print("Please enter the username to remove")
        user = input()
        self.client.sock.send(user.encode())
        response = self.client.sock.recv(BUFFSIZE).decode()
        print(response)


if __name__ == "__main__":
    Client().up()
