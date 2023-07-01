import socket
from threading import Thread
from entities import ClientInfo, Chat, Message, GroupInfo
from utils import send, receive

BUFFSIZE = 175

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
        try:
            while True:
                input_option = receive(conn)
                if input_option == "2":
                    if self.run_registration_menu(conn) and self.run_login_menu(conn): return
                if input_option == "1":
                    if self.run_login_menu(conn): return 
        except (ConnectionResetError, ConnectionAbortedError):
            print("An existing connection was forcibly closed by the remote host")

    def run_registration_menu(self, conn):
        username = receive(conn)  

        if username in self.clients or username in self.groups:
            send("Username Taken", conn)
            return False
        else:
            send("OK", conn)   
            password = receive(conn)
            send("ACK", conn)   # ACK
            elgamal_key = receive(conn)
            send("ACK", conn)   # ACK

            self.clients[username] = ClientInfo(username, password, conn, elgamal_key)
            return True
        
    def run_login_menu(self, conn):
        username = receive(conn)
        password = receive(conn)

        if username in self.clients and password == self.clients[username].password:
            send("OK", conn)
            self.online_clients.add(username)
            self.clients[username].conn = conn
            ClientHandler(self.clients[username], self).start()
            return True
        else:
            send("Login Failed", conn)
            return False


class ClientHandler(Thread):
    def __init__(self, client_info, server):
        Thread.__init__(self)
        self.client_info = client_info
        self.server = server

        self.APP_MENU_FUNCTIONS = [self.see_inbox, self.see_online_users, self.send_message, self.create_new_group, self.add_group_member, self.remove_group_member]

    def run(self):
        while True:
            message = receive(self.client_info.conn)
            print(f"Received '{message}' from {self.client_info.username}.")

            if not message:
                self.server.online_clients.remove(self.client_info.username)
                return
            
            input_option = int(message)
            try:
                self.APP_MENU_FUNCTIONS[input_option - 1]()
            except ConnectionResetError:
                print("An existing connection was forcibly closed by the remote host")
                break


    def see_inbox(self):
        new_chats = self.server.new_chats.get(self.client_info.username, {})
        send(f"{len(new_chats)}", self.client_info.conn)
        receive(self.client_info.conn)   # ACK
        for username in new_chats.keys():
            send(f"{username}", self.client_info.conn)
            receive(self.client_info.conn)   # ACK
            send(f"{len(new_chats[username].messages)}", self.client_info.conn)
            receive(self.client_info.conn)   # ACK
            for message in new_chats[username].messages:
                send(message.sender, self.client_info.conn)
                receive(self.client_info.conn)   # ACK
                send(message.C1, self.client_info.conn)
                receive(self.client_info.conn)   # ACK
                send(message.C2, self.client_info.conn)
                receive(self.client_info.conn)   # ACK

        self.server.new_chats[self.client_info.username] = {}

    def see_online_users(self):
        online_users_list = f"\n{'-'*20}\n".join(list(self.server.online_clients))
        send(online_users_list, self.client_info.conn)

    def send_message(self):
        self.see_inbox()

        username = receive(self.client_info.conn)
        if username not in self.server.clients and username not in self.server.groups:
            send("Username Not Found", self.client_info.conn)
            return
        else:
            send("OK", self.client_info.conn)

            self.resolve_elgamal_key(username)
            
            C1 = receive(self.client_info.conn)
            send("ACK", self.client_info.conn)    # ACK
            C2 = receive(self.client_info.conn)
            send("ACK", self.client_info.conn)    # ACK

            message = Message(self.client_info.username, C1=C1, C2=C2)
            if username in self.server.clients:
                self.send_private_message(username, message)
            else:
                self.send_group_message(username, message)

    def resolve_elgamal_key(self, username):
        request = receive(self.client_info.conn)
        if request == "OK": return
        
        elgamal_key = self.server.clients[username].elgamal_key
        send(elgamal_key, self.client_info.conn)

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
        print("at least im here :)")
        username = receive(self.client_info.conn)
        if username in self.server.clients or username in self.server.groups:
            send("Username Taken", self.client_info.conn)
            return
        else:
            send("OK", self.client_info.conn)
            members = self.get_group_member_set()
            self.server.groups[username] = GroupInfo(username, self.client_info.username, members)
            self.send_group_to_members(username)

    def get_group_member_set(self):
        member_count = int(receive(self.client_info.conn))
        
        members = set(self.client_info.username)
        for _ in range(member_count):
            user = receive(self.client_info.conn)
            if user not in self.server.clients:
                send("User Not Found", self.client_info.conn)
            else:
                send("User Added", self.client_info.conn)
                members.add(user)
    
        return members
    
    def send_group_to_members(self, username):
        for member in self.server.groups[username].members:
            self.send_group_to_member(username, member)

    def send_group_to_member(self, username, member):
        if member not in self.server.new_chats: self.server.new_chats[member] = {}
        self.server.new_chats[member][username] = Chat(username)

    def add_group_member(self):
        username = receive(self.client_info.conn)
        if username not in self.server.groups:
            send("Group Not Found", self.client_info.conn)
            return
        # TODO: control authenticity of the message in upper layer
        if self.client_info.username != self.server.groups[username].owner:
            send("Permission Denied", self.client_info.conn)
            return
        else:
            send("OK", self.client_info.conn)
            user = receive(self.client_info.conn)
            if user not in self.server.clients:
                send("User Not Found", self.client_info.conn)
            else:
                send("User Added", self.client_info.conn)
                self.server.groups[username].members.add(user)
                self.send_group_to_member(username, user)


    def remove_group_member(self):
        username = receive(self.client_info.conn)
        if username not in self.server.groups:
            send("Group Not Found", self.client_info.conn)
            return
        # TODO: control authenticity of the message in upper layer
        if self.client_info.username != self.server.groups[username].owner:
            send("Permission Denied", self.client_info.conn)
            return
        else:
            send("OK", self.client_info.conn)
            user = receive(self.client_info.conn)
            if user not in self.server.groups[username].members:
                send("User Not a Member of This Group", self.client_info.conn)
            else:
                send("User Removed", self.client_info.conn)
                self.server.groups[username].members.remove(user)


if __name__ == "__main__":
    Server().up()

