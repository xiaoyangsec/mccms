**Exploit Title: MCCMS Server-Side Request Forgery (SSRF) Vulnerability (Unauthenticated)**

**Version: CTCMS v2.7.0**

**Google Dork: N/A**

**Date: 04/28/2025**

**Tested on: Apache2.4, MySQL5.7, PHP7.3**

**Software Link: https://www.mccms.cn/**

**Description: This application has an SSRF vulnerability located in the index() method of the sys\apps\controllers\api\Gf.php file, where the pic parameter is processed. The pic parameter is decrypted using the sys_auth($pic, 1) function, which utilizes a hard-coded key Mc_Encryption_Key (bD2voYwPpNuJ7B8), defined in the db.php file. The decrypted URL is passed to the geturl() method, which uses cURL to make a request to the URL without proper security checks. An attacker can craft a malicious encrypted pic parameter, which, when decrypted, points to internal addresses or local file paths (such as http://127.0.0.1 or file://). By using the file:// protocol, the attacker can access arbitrary files on the local file system (e.g., file:///etc/passwd, file:///C:/Windows/System32/drivers/etc/hosts), allowing them to read sensitive configuration files, log files, and more, leading to information leakage or system exposure. The danger of this SSRF vulnerability includes accessing internal services and local file systems through protocols like http://, ftp://, and file://, which can result in sensitive data leakage, remote code execution, privilege escalation, or full system compromise, severely affecting the system's security and stability.**
![image](https://github.com/user-attachments/assets/03e91507-1921-4136-9677-194e37a35293)
![image](https://github.com/user-attachments/assets/7ba78941-2777-4609-b095-d71da7bfe326)
![image](https://github.com/user-attachments/assets/468490fa-48e9-48d4-8a97-3089e3caf497)

Payload used:
```
GET /index.php/api/gf/?pic=Qq6XqoI-6Gg9fTON51lmQzswca2YHCQug4NM3jNzxw6fmksL8ZqmqBUtBJ/HPC8HYPZAX-vyY-gj/jjkIMnMjmcE/eVzHQlBvbc HTTP/1.1
Host: www.mccms.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```

Example：
1. Craft and Send the Malicious Request: Modify the pic parameter to point to an internal address or local file (e.g., http://127.0.0.1 or file://), then send the request to the server, exploiting the SSRF vulnerability.
2. Below is a screenshot showing the successful request and the server’s response, confirming the exploitation.
![image](https://github.com/user-attachments/assets/784bff2d-8303-4f33-8b7b-01a963f81619)


Craft and Send the Malicious Request: Using poc.py, modify the pic parameter to point to http://127.0.0.1:3306 to probe for the internal MySQL database port, or use file://C:/Windows/win.ini to attempt reading the win.ini file.

Screenshot: Below is a screenshot showing the successful exploitation of the SSRF vulnerability.
![image](https://github.com/user-attachments/assets/62c2fddb-dbe7-4922-a5c1-c999d4a44d26)

![image](https://github.com/user-attachments/assets/016ba69e-156a-402f-9047-c7fe44cd9de3)

