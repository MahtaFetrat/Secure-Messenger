import socket
from threading import Thread
from entities import ClientInfo, Chat, Message, GroupInfo

BUFFSIZE = 1024

class Server:
    IP = "127.0.0.1"
    PORT = 50000

    def __init__(self):
        self.socket = socket.socket()
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.clients = {}
        self.online_clients = set()

        self.groups = {}

        self.new_chats = {}     # dict of (key=user1 who has new chat, value=incomming chat for user1) 
        # { mahta: {
        #            fatemeh,
        #            zeinab,
        #           },
        #   mitra: {
        #            fatemeh
        #          }
        #   zeinab: {
        #           }
        # }

    def up(self):
        self.socket.bind((Server.IP, Server.PORT))
        self.socket.listen()
        print(f"Server listening on {Server.IP}:{Server.PORT}.")

        self.listen_for_connections()

    def listen_for_connections(self):
        while True:
            conn, addr = self.socket.accept()
            Thread(target=self.handle_connection, args=(conn,)).start()

    def handle_connection(self, conn):
        input_option = conn.recv(BUFFSIZE).decode()
        if input_option == "2":
            if self.run_registration_menu(conn):
                self.run_login_menu(conn)
        if input_option == "1":
            self.run_login_menu(conn)               

    def run_registration_menu(self, conn):
        username = conn.recv(BUFFSIZE).decode()  

        if username in self.clients or username in self.groups:
            conn.send("Username Taken".encode())
            return False
        else:
            conn.send("OK".encode())   
            password = conn.recv(BUFFSIZE).decode()
            self.clients[username] = ClientInfo(username, password, conn)
            return True
        
    def run_login_menu(self, conn):
        username = conn.recv(BUFFSIZE).decode()
        password = conn.recv(BUFFSIZE).decode()

        if username in self.clients and password == self.clients[username].password:
            conn.send("OK".encode())
            self.online_clients.add(username)
            self.clients[username].conn = conn
            ClientHandler(self.clients[username], self).start()
        else:
            conn.send("Login Failed".encode())

class ClientHandler(Thread):
    def __init__(self, client_info, server):
        Thread.__init__(self)
        self.client_info = client_info
        self.server = server

        self.APP_MENU_FUNCTIONS = [self.see_inbox, self.see_online_users, self.send_message, self.create_new_group, self.add_group_member, self.remove_group_member]

    def run(self):
        while True:
            message = self.client_info.conn.recv(1024).decode()

            if not message:
                self.server.online_clients.remove(self.client_info.username)
                return
            
            input_option = int(message)
            self.APP_MENU_FUNCTIONS[input_option - 1]()

            print(f"Received '{message}' from {self.client_info.username}.")

    def see_inbox(self):
        new_chats = self.server.new_chats.get(self.client_info.username, {})
        self.client_info.conn.send(f"{len(new_chats)}".encode())
        for username in new_chats.keys():
            self.client_info.conn.send(f"{username}".encode())
            self.client_info.conn.recv(BUFFSIZE).decode()   # ACK
            self.client_info.conn.send(f"{len(new_chats[username].messages)}".encode())
            self.client_info.conn.recv(BUFFSIZE).decode()   # ACK
            for message in new_chats[username].messages:
                self.client_info.conn.send(message.sender.encode())
                self.client_info.conn.recv(BUFFSIZE).decode()   # ACK
                self.client_info.conn.send(message.text.encode())
                self.client_info.conn.recv(BUFFSIZE).decode()   # ACK

        self.server.new_chats[self.client_info.username] = {}

    def see_online_users(self):
        online_users_list = f"\n{'-'*20}\n".join(list(self.server.online_clients))
        self.client_info.conn.send(online_users_list.encode())

    def send_message(self):
        username = self.client_info.conn.recv(BUFFSIZE).decode()
        if username not in self.server.clients and username not in self.server.groups:
            self.client_info.conn.send("Username Not Found".encode())
            return
        else:
            self.client_info.conn.send("OK".encode())
            
            message = Message(self.client_info.username, self.client_info.conn.recv(BUFFSIZE).decode())
            if username in self.server.clients:
                self.send_private_message(username, message)
            else:
                self.send_group_message(username, message)

    def send_private_message(self, username, message):
        if username not in self.server.new_chats: self.server.new_chats[username] = {}
        if self.client_info.username not in self.server.new_chats[username]:
            self.server.new_chats[username][self.client_info.username] = Chat(self.client_info.username)
        self.server.new_chats[username][self.client_info.username].messages.append(message)

    def send_group_message(self, username, message):
        for member in self.server.groups[username].members:
            if member == self.client_info.username: continue
            if member not in self.server.new_chats:
                self.server.new_chats[member] = {}
            if username not in self.server.new_chats[member]:
                self.server.new_chats[member][username] = Chat(username)
            self.server.new_chats[member][username].messages.append(message)

    def create_new_group(self):
        username = self.client_info.conn.recv(BUFFSIZE).decode()
        if username in self.server.clients or username in self.server.groups:
            self.client_info.conn.send("Username Taken".encode())
            return
        else:
            self.client_info.conn.send("OK".encode())
            members = self.get_group_member_set()
            self.server.groups[username] = GroupInfo(username, self.client_info.username, members)
            self.send_group_to_members(username)

    def get_group_member_set(self):
        member_count = int(self.client_info.conn.recv(BUFFSIZE).decode())
        
        members = set(self.client_info.username)
        for _ in range(member_count):
            user = self.client_info.conn.recv(BUFFSIZE).decode()
            if user not in self.server.clients:
                self.client_info.conn.send("User Not Found".encode())
            else:
                self.client_info.conn.send("User Added".encode())
                members.add(user)
    
        return members
    
    def send_group_to_members(self, username):
        for member in self.server.groups[username].members:
            self.send_group_to_member(username, member)

    def send_group_to_member(self, username, member):
        if member not in self.server.new_chats: self.server.new_chats[member] = {}
        self.server.new_chats[member][username] = Chat(username)

    def add_group_member(self):
        username = self.client_info.conn.recv(BUFFSIZE).decode()
        if username not in self.server.groups:
            self.client_info.conn.send("Group Not Found".encode())
            return
        else:
            self.client_info.conn.send("OK".encode())
            user = self.client_info.conn.recv(BUFFSIZE).decode()
            if user not in self.server.clients:
                self.client_info.conn.send("User Not Found".encode())
            else:
                self.client_info.conn.send("User Added".encode())
                self.server.groups[username].members.add(user)
                self.add_group_member(username, user)


    def remove_group_member(self):
        username = self.client_info.conn.recv(BUFFSIZE).decode()
        if username not in self.server.groups:
            self.client_info.conn.send("Group Not Found".encode())
            return
        else:
            self.client_info.conn.send("OK".encode())
            user = self.client_info.conn.recv(BUFFSIZE).decode()
            if user not in self.server.groups[username].members:
                self.client_info.conn.send("User Not a Member of This Group".encode())
            else:
                self.client_info.conn.send("User Removed".encode())
                self.server.groups[username].members.remove(user)


if __name__ == "__main__":
    Server().up()

