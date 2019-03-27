'''
This is the implementation of a mail filter for keyforge

'''

import json
import socket
import sys
import os

'''
def main():
    print("Hello World!")

if __name__== "__main__":
    main()

'''


# Create a socket
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

# Connect the socket to the port where the server is listening
server_address = '/tmp/kf.sock'

print('connecting to %s' % server_address)
try:
    sock.connect(server_address)
except socket.error:
    sys.exit(1)

args = {
        "Sha256":"asdf",
        "ReceiverEmailAddress":"foo@bar.com"
}

payload = {
	"method": "Server.Sign",
	"params": [args],
	"jsonrpc": "2.0",
	"id": 0,
	}

sock.sendall(json.dumps(payload).encode())

data = sock.recv(1000)
result = json.loads(data)
print("Sign result:")
print(json.dumps(result, indent=4, sort_keys=True))

'''
type VerifyArgs struct {
	Sha256             string // A sha256 sum of the message to be verified
	SenderEmailAddress string // The email address of the receiver
	DNS                string // The DNS we should use to look up params (specified in the header)
	Signature          string // The sig
	Expiry             string // The time at which the key expires
}
'''

args = {
        "Sha256":"asdf",
        "SenderEmailAddress":"foo@bar.com",
        "DNS":"_KeyForge.example.com" , # REPLACE WITH YOUR URL
        "Signature":result['result']['Signature'],
        "Expiry":result['result']['Expiry']
}

payload = {
	"method": "Server.Verify",
	"params": [args],
	"jsonrpc": "2.0",
	"id": 0,
	}


sock.sendall(json.dumps(payload).encode())
data = sock.recv(1000)
result = json.loads(data)
print("Verify result:")
print(json.dumps(result, indent=4, sort_keys=True))

