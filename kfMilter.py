"""
This is the implementation of a mail filter for keyforge

We only verify a subset of the items usually required for DKIM:
    - from
    - to
    - cc
    - content-type
    - content-transfer-encoding
    - mime-version
    - date
    - references 
    - reply-to 
    - message-id
    - subject
"""

import io 
import json
import socket
import sys
import os
import Milter
import hashlib
from email.header import decode_header
from email.utils import parseaddr


MY_DOMAIN = "deniable.email"
MY_SELECTOR = "_keyforge"
KF_SOCK = "/tmp/kf.sock"

KF_HEADER = "keyforge-signature"

SIG_FIELDS = [
        "from",
        "to",
        "cc",
        "content-type",
        "content-transfer-encoding",
        "mime-version",
        "date",
        "references ",
        "reply-to ",
        "message-id",
        "subject"
        ]


def tagToDict(tagValList):
    tagValList = [tv.split('=',1) for tv in tagValList.split(';')]

    return {k:v for (k,v) in tagValList}

def dictToTV(tvDict):
    result = ""
    for k in tvDict:
        v = tvDict[k]
        result += k + '=' + v + ';'
    return result


def getSock():
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

    try:
        sock.connect(KF_SOCK)
    except socket.error:
        sys.exit(1)

    return sock


def kfSignRPC(message):
    """
    Performs an rpc to the keyforge server
    """

    sock = getSock()
    hashval = hashlib.sha256(message).hexdigest()

    args = {"Sha256":hashval}
    payload = {
            "method": "Server.Sign",
            "params": [args],
            "jsonrpc": "2.0",
            "id": hashval,
            }

    sock.sendall(json.dumps(payload).encode())

    data = sock.recv(1000)
    result = json.loads(data)

    print("Sign result:")
    print(json.dumps(result, indent=4, sort_keys=True))

    return result, hashval


def kfVerifyRPC(message, sig, sentHash, expiry, dns):
    """
    returns false if kfVerify fails
    """

    sock = getSock()
    hashval = hashlib.sha256(message).hexdigest()

    if hashval != sentHash:
        return False

    args = {
            "Sha256":hashval,
            "DNS":dns,
            "Signature":sig,
            "Expiry":expiry
    }

    payload = {
            "method": "Server.Verify",
            "params": [args],
            "jsonrpc": "2.0",
            "id": hashval,
            }


    sock.sendall(json.dumps(payload).encode())

    data = sock.recv(1000)
    result = json.loads(data)
    print("verify result:")
    print(json.dumps(result, indent=4, sort_keys=True))

    return result

def canonicalizeAndVerify(headers, body):
    """
    creates a canonicalized message and passes it to verify
    """

    # Sanity check, this isn't signed by our list
    if KF_HEADER not in headers:
        return None

    kfHeader = tagToDict(headers[KF_HEADER])

    # h tells us what should exist in the header and what order
    messageHeaders = kfHeader['h']

    # d tells us the dns name
    # s is the selector 
    # full dns = selector.dns
    fullDNS = kfHeader['s'] + '.' + kfHeader['d']

    # x is the expiry time in UTC
    expiry = kfHeader['x']

    # bh is the original hash of the message
    sentHash = kfHeader['bh']

    canonMessage = body

    for headerField in messageHeaders.split(':'):
        message += headers[headerField]

    verResult = kfVerifyRPC(message, sig, sentHash, expiry, fullDNS)
    if verResult == False or verResult["error"] != None or verResult["result"]['Success'] == False:
        return False

    return verResult['result']['Answer']

def canonicalizeAndSign(headers, body):
    """
    returns the canonicalized message to be signed 
    """
    message = body
    fields = []
    for hval in SIG_FIELDS:
        if hval in headers:
            message += str.encode(headers[hval])
            fields.append(hval)

    sigResult, hashval = kfSignRPC(message)

    # check if sign result worked:
    if sigResult["error"] != None or sigResult["result"]["Success"] == False:
        return False

    result = sigResult['result']

    kfHeader = {
            'h' : ':'.join(fields),   # h is what should exist in the header and what order
            'd' : MY_DOMAIN,          # d tells us the dns name
            's' : '_keyforge',        # s is the selector 
            'x' : result['Expiry'],   # x is the expiry time
            'bh': hashval,            # bh is the original hash of the message
            'b' : result['Signature'] # b is the actual signature
            }

    return dictToTV(kfHeader)

class KeyForge(Milter.Base):
    """
    kf milter function
    """
    
    def __init__(self):
        self.__id = Milter.uniqueID()
        self.__mail_from = ""
        self.__header = None
        self.__fp = None
        self.__user = False

    @Milter.noreply
    def envfrom(self, mailfrom, *dummy):
        """
        Callback that is called when MAIL FROM: is recognized.
        A connection can have multiple emails. This is the beginning of an email
        """
        self.__fp = io.BytesIO()
        self.__mail_from = parseaddr(mailfrom)[1]
        self.__header = dict()

        # Tells us if this is an authenticated user
        # specifically, if this message needs to be signed
        self.__user = self.getsymval('{auth_authen}')

        return Milter.CONTINUE

    @Milter.noreply
    def header(self, name, hval):
        """
        Called for each header
        We record all headers
        """
        print("_"*80)
        print("WE HAVE A HEADER:")
        print("%s: %s" % (name, hval))

        # Record header info
        self.__header[name.lower()] = hval

        return Milter.CONTINUE

    @Milter.noreply
    def body(self,chunk):
        print(type(chunk))
        self.__fp.write(chunk)
        return Milter.CONTINUE

    def eoh(self):
        """
        eoh = the End of Header. 
        This is called after all headers have been proccessed
        """
        print("*"*80)
        print("End of header")

        return Milter.CONTINUE

    def eom(self):
        """
        eom - end of message.
        """
        print("from", self.__mail_from[1])
        print("EOM", self.__header)

        print("*"*80)
        print(self.__mail_from)

        # Shows that a user has submitted the following:
        if self.__user:
            body = self.__fp.getvalue()
            result = canonicalizeAndSign(self.__header, body)
            if result == False:
                # Fail! Badness occured
                print("failure in signing, badness occurred in the kf server!")
            else:
                print("Message Signed! Adding Header")
                print(result)
                self.addheader(KF_HEADER, result)

        return Milter.CONTINUE

    def close(self):
        """close callback"""
        print("close")
        return Milter.CONTINUE

if __name__ == "__main__":
    socketname = "/var/spool/postfix/kf/kf.sock"
    Milter.factory = KeyForge
    Milter.set_flags(Milter.CHGBODY + Milter.CHGHDRS + Milter.ADDHDRS)
    Milter.runmilter("pythonfilter", socketname, 240)

    print("milter shutdown")


