class ClientInfo:
    def __init__(self, username, password, conn, elgamal_key):
        self.username = username
        self.password = password
        self.conn = conn
        self.elgamal_key = elgamal_key

class GroupInfo:
    def __init__(self, username, owner, members):
        self.username = username
        self.owner = owner
        self.members = members

class Chat:
    def __init__(self, username):
        self.username = username
        self.unread_message_count = 0
        self.messages = []


class Message:
    def __init__(self, sender, text="", C1="", C2=""):
        self.sender = sender
        self.text = text
        self.C1 = C1
        self.C2 = C2

    

