import base64
from Crypto.Random import get_random_bytes
from Crypto.Cipher import DES, DES3, AES
from Crypto.Util.Padding import pad, unpad

def normalize_key(key: str, new_len: int) -> bytes:
    bytes_key = key.encode('utf-8')
    if (len(bytes_key) > new_len):
        return bytes_key[:new_len]
    elif (len(bytes_key) < new_len):
        needed_size = new_len - len(bytes_key)
        pad = get_random_bytes(needed_size)
        return bytes_key + pad
    else:
        return bytes_key


def encrypt_des_cbc(input: str, key: bytes, iv: bytes) -> str:
    cipher = DES.new(key, DES.MODE_CBC, iv)
    plaintext = input.encode('utf-8')
    textpadded = pad(plaintext, 8)
    msg = cipher.encrypt(textpadded)

    return msg

def decrypt_des_cbc(input: bytes, key: bytes, iv: bytes) -> str:
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    msg = cipher.decrypt(input)
    msg_unpadded = unpad(msg, 8)
    return msg_unpadded

def encrypt_des3_cbc(input: str, key: bytes, iv: bytes) -> str:
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    plaintext = input.encode('utf-8')
    textpadded = pad(plaintext, 8)
    msg = cipher.encrypt(textpadded)

    return msg

def decrypt_des3_cbc(input: bytes, key: bytes, iv: bytes) -> str:
    cipher = DES3.new(key, DES.MODE_CBC, iv)
    msg = cipher.decrypt(input)
    msg_unpadded = unpad(msg, 8)
    return msg_unpadded


def encrypt_aes256_cbc(pinput: str, key: bytes,  iv: bytes) -> str:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    b = pinput.encode("UTF-8")
    textpadded = pad(b, 16)
    return cipher.encrypt(textpadded)

def decrypt_aes256_cbc(input: bytes, key: bytes, iv: bytes) -> str:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    msg = cipher.decrypt(input)
    msg_unpadded = unpad(msg, 16)
    return msg_unpadded

def bytes_b64(input: bytes) -> None:
    return base64.b64encode(input).decode('utf-8')

def maindes3(input: str, key: str, iv: bytes) -> None:
    assert len(iv) == 8

    new_key = normalize_key(key, 8)
    print(f"LLave ajustada: {new_key}\n")
    msg = encrypt_des_cbc(input, new_key, iv)
    msg_b64 = bytes_b64(msg)
    print(f"Texto encriptado (representacion en Base64): {msg_b64}")
    msg_de = decrypt_des_cbc(msg, new_key, iv)
    print(f"Texto desencriptado: {msg_de}")

def maindes3(input: str, key1: str, key2: str, key3: str, iv: bytes) -> None:
    assert len(iv) == 8

    new_key1 = normalize_key(key1, 8)
    new_key2 = normalize_key(key2, 8)
    new_key3 = normalize_key(key3, 8)
    new_key = new_key1 + new_key2 + new_key3
    print(f"LLave ajustada: {new_key}\n")
    msg = encrypt_des3_cbc(input, new_key, iv)
    msg_b64 = bytes_b64(msg)
    print(f"Texto encriptado (representacion en Base64): {msg_b64}")
    msg_de = decrypt_des3_cbc(msg, new_key, iv)
    print(f"Texto desencriptado: {msg_de}")

def mainaes256(input: str, key: str, iv: bytes) -> None:
    #assert len(key) == 32
    assert len(iv) == 16

    new_key = normalize_key(key, 32)
    print(f"new_key : {new_key} \n")

    msg = encrypt_aes256_cbc(input, new_key, iv)
    msg_b64 = bytes_b64(msg)
    print(f"Texto encriptado (representacion en Base64): {msg_b64}")

    msg_de = decrypt_aes256_cbc(msg, new_key, iv)
    print(f"Texto desencriptado: {msg_de}")

def main() -> None:
    inputText = "texto"
    key1 = "12345678911234561234567891123456"
    key2 = "20391029"
    key3 = "74829103"
    iv = b'12345678' # 8 bytes
    iv16 = b'1234567891123456' # 16 bytes
    #maindes3(inputText, key1, key2, key3, iv)

    mainaes256(inputText, key1, iv16)

if __name__ == "__main__":
    main()
