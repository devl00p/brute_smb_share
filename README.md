# brute_smb_share

I wrote this small PoC after bumping into SMB servers where Hydra, Nmap, Medusa and CrackMapExec all failed to discover valid credentials correctly.

The script uses the official Python library from the Samba project, not Impacket, not PySMB.

You may find the library with a name like "samba-python3" in your package manager.

MIT Licence
