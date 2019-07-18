'''
Implements a class used by cslogwatch to hold cobalt strike log
entry data in objects
'''

import json

class CSLogEntry(object):
    '''
    Class that implements a Cobalt Strik Log Entry object
    with associated getter and setter functions
    '''
    timestamp = None
    event_type = None
    computer = None
    ip_address = None
    pid = None
    username = None
    content = None

    def get_timestamp(self):
        ''' Returns CSLogEntry object timestamp  '''
        return self.timestamp

    def set_timestamp(self, timestamp):
        ''' Sets CSLogEntry object timestamp  '''
        self.timestamp = timestamp

    def get_event_type(self):
        ''' Returns CSLogEntry object event type  '''
        return self.event_type

    def set_event_type(self, event_type):
        ''' Sets CSLogEntry object event type  '''
        self.event_type = event_type

    def get_computer(self):
        ''' Returns CSLogEntry object computer  '''
        return self.computer

    def set_computer(self, computer):
        ''' Sets CSLogEntry object computer  '''
        self.computer = computer

    def get_ip_address(self):
        ''' Returns CSLogEntry object IP address  '''
        return self.ip_address

    def set_ip_address(self, ip_address):
        ''' Sets CSLogEntry object IP address  '''
        self.ip_address = ip_address

    def get_pid(self):
        ''' Returns CSLogEntry object PID  '''
        return self.pid

    def set_pid(self, pid):
        ''' Sets CSLogEntry object PID  '''
        self.pid = pid

    def get_content(self):
        ''' Returns CSLogEntry object content  '''
        return self.content

    def set_content(self, content):
        ''' Sets CSLogEntry object content  '''
        self.content = content

    def get_username(self):
        ''' Returns CSLogEntry object username  '''
        return self.username

    def set_username(self, username):
        ''' Sets CSLogEntry object username  '''
        self.username = username

    def to_json(self):
        ''' Returns a JSON string of the CSLogEntry object  '''
        return json.dumps(self.to_dict())


    def to_dict(self):
        ''' Returns a dict of the CSLogEntry object  '''
        return {
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "computer" : self.computer,
            "ip_address" : self.ip_address,
            "pid" : self.pid,
            "username" : self.username,
            "content" : self.content
        }
