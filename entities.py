class ClientInfo:
    def __init__(self, username, password, conn):
        self.username = username
        self.password = password
        self.conn = conn

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
    def __init__(self, sender, text):
        self.sender = sender
        self.text = text

