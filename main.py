
from scapy.all import  UDP,RandShort,send,LLMNRQuery,LLMNRResponse,IP,Ether,sniff,DNSQR
import string
import random
import threading
from smbprotocol.connection import Connection
from smbprotocol.session import Session
import uuid
import exrex

def recieve_packet(packet,
                   usernameRegex = '/^[a-zA-Z][a-zA-Z0-9\-\.]{0,61}[a-zA-Z]\\\w[\w\.\- ]+$/',
                   passwordRegex = '^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[*.!@$%^&(){}[]:;<>,.?/~_+-=|\]).{8,32}$'):
    ip = packet[Ether][IP][UDP][LLMNRResponse].an.rdata
    print( packet[Ether][IP][UDP][LLMNRResponse].an.rdata)
    
    while True:
        try:
            username = generate_from_regex(usernameRegex)
            password = generate_from_regex(passwordRegex)
            connection = Connection(uuid.uuid4(), ip, 139,require_signing=False)
            connection.connect()
            session = Session(connection,username , password)
            session.connect()
        except:
            continue

def sniffing():
    sniff(filter="udp dst port 5355",count=1,prn=recieve_packet,iface="en0")

def generate_from_regex(regex):
    return exrex.getone(regex)


def randomString(stringLength=10):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))

packet = IP(dst="224.0.0.252",src="192.168.178.232")/UDP(sport=5355,dport=5355)/LLMNRQuery(id=RandShort(), qd=DNSQR(qname=randomString()))
packet.show()

t = threading.Thread(target=sniffing)
t.start()
send(packet,iface="en0")
t.join()

