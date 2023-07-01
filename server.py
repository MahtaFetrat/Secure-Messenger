import socket
from threading import Thread
from entities import ClientInfo, Chat, Message, GroupInfo
from utils import send, receive
from elgamal import ElgamalKey

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

        self.new_chats = {}

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
                input_option = conn.recv(BUFFSIZE).decode()
                if input_option == "2":
                    if self.run_registration_menu(conn) and self.run_login_menu(conn): return
                if input_option == "1":
                    if self.run_login_menu(conn): return 
        except (ConnectionResetError, ConnectionAbortedError):
            print("An existing connection was forcibly closed by the remote host")

    def run_registration_menu(self, conn):
        username = conn.recv(BUFFSIZE).decode()

        if username in self.clients or username in self.groups:
            conn.send("Username Taken".encode())
            return False
        else:
            conn.send("OK".encode())

            print("here")

            password = receive(conn, ('private_key.pem', f'public_key_{username}.pem', 'SERVER'))
            print('there',password)
            send("ACK", conn, (f'public_key_{username}.pem', 'private_key.pem', 'SERVER'))   # ACK

            print("here")
            
            q = receive(conn, ('private_key.pem', f'public_key_{username}.pem', 'SERVER'))
            send("ACK", conn, (f'public_key_{username}.pem', 'private_key.pem', 'SERVER'))   # ACK
            α = receive(conn, ('private_key.pem', f'public_key_{username}.pem', 'SERVER'))
            send("ACK", conn, (f'public_key_{username}.pem', 'private_key.pem', 'SERVER'))   # ACK
            Y = receive(conn, ('private_key.pem', f'public_key_{username}.pem', 'SERVER'))
            send("ACK", conn, (f'public_key_{username}.pem', 'private_key.pem', 'SERVER'))   # ACK

            print("here")

            elgamal_key = ElgamalKey(q, α, Y)

            self.clients[username] = ClientInfo(username, password, conn, elgamal_key)
            return True
        
    def run_login_menu(self, conn):
        username = receive(conn, ('private_key.pem', f'public_key_{username}.pem', 'SERVER'))
        password = receive(conn, ('private_key.pem', f'public_key_{username}.pem', 'SERVER'))

        if username in self.clients and password == self.clients[username].password:
            send("OK", conn, (f'public_key_{username}.pem', 'private_key.pem', 'SERVER'))
            self.online_clients.add(username)
            self.clients[username].conn = conn
            ClientHandler(self.clients[username], self).start()
            return True
        else:
            send("Login Failed", conn, (f'public_key_{username}.pem', 'private_key.pem', 'SERVER'))
            return False


class ClientHandler(Thread):
    def __init__(self, client_info, server):
        Thread.__init__(self)
        self.client_info = client_info
        self.server = server

        self.send_parameters = f'public_key_{self.client_info.username}.pem', 'private_key.pem', 'SERVER'
        self.receive_parameters = 'private_key.pem', f'public_key_{self.client_info.username}.pem', 'SERVER'

        self.APP_MENU_FUNCTIONS = [self.see_inbox, self.see_online_users, self.send_message, self.create_new_group, self.add_group_member, self.remove_group_member]

    def run(self):
        while True:
            try:
                message = receive(self.client_info.conn, self.receive_parameters)
                print(f"Received '{message}' from {self.client_info.username}.")

                if not message:
                    self.server.online_clients.remove(self.client_info.username)
                    return
                
                input_option = int(message)
                self.APP_MENU_FUNCTIONS[input_option - 1]()
            except (ConnectionResetError, ConnectionAbortedError):
                print("An existing connection was forcibly closed by the remote host")
                break


    def see_inbox(self):
        new_chats = self.server.new_chats.get(self.client_info.username, {})
        send(f"{len(new_chats)}", self.client_info.conn, self.send_parameters)
        receive(self.client_info.conn, self.receive_parameters)   # ACK
        for username in new_chats.keys():
            send(f"{username}", self.client_info.conn, self.send_parameters)
            receive(self.client_info.conn, self.receive_parameters)   # ACK
            send(f"{len(new_chats[username].messages)}", self.client_info.conn, self.send_parameters)
            receive(self.client_info.conn, self.receive_parameters)   # ACK
            for message in new_chats[username].messages:
                send(message.sender, self.client_info.conn, self.send_parameters)
                receive(self.client_info.conn, self.receive_parameters)   # ACK
                send(message.C1, self.client_info.conn, self.send_parameters)
                receive(self.client_info.conn, self.receive_parameters)   # ACK
                send(message.C2, self.client_info.conn, self.send_parameters)
                receive(self.client_info.conn, self.receive_parameters)   # ACK

        self.server.new_chats[self.client_info.username] = {}

    def see_online_users(self):
        online_users_list = f"\n{'-'*20}\n".join(list(self.server.online_clients))
        send(online_users_list, self.client_info.conn, self.send_parameters)

    def send_message(self):
        self.see_inbox()

        username = receive(self.client_info.conn, self.receive_parameters)
        if username not in self.server.clients and username not in self.server.groups:
            send("Username Not Found", self.client_info.conn, self.send_parameters)
            return
        if username in self.server.clients:
            send("User Found", self.client_info.conn, self.send_parameters)
            self.send_message_to_user(username, self.client_info.username)
        else:
            send("Group Found", self.client_info.conn, self.send_parameters)
            self.send_message_to_group(username)

    def send_message_to_user(self, username, sender_username):
        self.resolve_elgamal_key(username)
        
        C1 = receive(self.client_info.conn, self.receive_parameters)
        send("ACK", self.client_info.conn, self.send_parameters)    # ACK
        C2 = receive(self.client_info.conn, self.receive_parameters)
        send("ACK", self.client_info.conn, self.send_parameters)    # ACK

        message = Message(self.client_info.username, C1=C1, C2=C2)
        if username not in self.server.new_chats: self.server.new_chats[username] = {}
        if sender_username not in self.server.new_chats[username]:
            self.server.new_chats[username][sender_username] = Chat(sender_username)
        self.server.new_chats[username][sender_username].messages.append(message)
        
    def send_message_to_group(self, username):
        send(f"{len(self.server.groups[username].members) - 1}", self.client_info.conn, self.send_parameters)
        receive(self.client_info.conn, self.receive_parameters)     # ACK

        for member in self.server.groups[username].members:
            if member == self.client_info.username: continue
            send(member, self.client_info.conn, self.send_parameters)
            receive(self.client_info.conn, self.receive_parameters)  # ACK

            self.send_message_to_user(member, username, self.send_parameters)

    def resolve_elgamal_key(self, username):
        request = receive(self.client_info.conn, self.receive_parameters)
        if request == "OK": return
        
        elgamal_key = self.server.clients[username].elgamal_key
        send(elgamal_key.q, self.client_info.conn, self.send_parameters)
        receive(self.client_info.conn, self.receive_parameters)     # ACK
        send(elgamal_key.α, self.client_info.conn, self.send_parameters)
        receive(self.client_info.conn, self.receive_parameters)     # ACK
        send(elgamal_key.Y, self.client_info.conn, self.send_parameters)

    def create_new_group(self):
        username = receive(self.client_info.conn, self.receive_parameters)
        if username in self.server.clients or username in self.server.groups:
            send("Username Taken", self.client_info.conn, self.send_parameters)
            return
        else:
            send("OK", self.client_info.conn, self.send_parameters)
            members = self.get_group_member_set()
            self.server.groups[username] = GroupInfo(username, self.client_info.username, members)
            self.send_group_to_members(username)

    def get_group_member_set(self):
        member_count = int(receive(self.client_info.conn, self.receive_parameters))
        
        members = set(self.client_info.username)
        for _ in range(member_count):
            user = receive(self.client_info.conn, self.receive_parameters)
            if user not in self.server.clients:
                send("User Not Found", self.client_info.conn, self.send_parameters)
            else:
                send("User Added", self.client_info.conn, self.send_parameters)
                members.add(user)
    
        return members
    
    def send_group_to_members(self, username):
        for member in self.server.groups[username].members:
            self.send_group_to_member(username, member)

    def send_group_to_member(self, username, member):
        if member not in self.server.new_chats: self.server.new_chats[member] = {}
        self.server.new_chats[member][username] = Chat(username)

    def add_group_member(self):
        username = receive(self.client_info.conn, self.receive_parameters)
        if username not in self.server.groups:
            send("Group Not Found", self.client_info.conn, self.send_parameters)
            return
        # TODO: control authenticity of the message in upper layer
        if self.client_info.username != self.server.groups[username].owner:
            send("Permission Denied", self.client_info.conn, self.send_parameters)
            return
        else:
            send("OK", self.client_info.conn, self.send_parameters)
            user = receive(self.client_info.conn, self.receive_parameters)
            if user not in self.server.clients:
                send("User Not Found", self.client_info.conn, self.send_parameters)
            else:
                send("User Added", self.client_info.conn, self.send_parameters)
                self.server.groups[username].members.add(user)
                self.send_group_to_member(username, user)


    def remove_group_member(self):
        username = receive(self.client_info.conn, self.receive_parameters)
        if username not in self.server.groups:
            send("Group Not Found", self.client_info.conn, self.send_parameters)
            return
        # TODO: control authenticity of the message in upper layer
        if self.client_info.username != self.server.groups[username].owner:
            send("Permission Denied", self.client_info.conn, self.send_parameters)
            return
        else:
            send("OK", self.client_info.conn, self.send_parameters)
            user = receive(self.client_info.conn, self.receive_parameters)
            if user not in self.server.groups[username].members:
                send("User Not a Member of This Group", self.client_info.conn, self.send_parameters)
            else:
                send("User Removed", self.client_info.conn, self.send_parameters)
                self.server.groups[username].members.remove(user)


if __name__ == "__main__":
    Server().up()

