import base64
from Crypto.Random import get_random_bytes
from Crypto.Cipher import DES, DES3, AES
from Crypto.Util.Padding import pad, unpad

def normalize_bytes(data: str, new_len: int, label: str = "Dato") -> bytes:
    bytes_data = data.encode('utf-8')

    if len(bytes_data) > new_len:
        print(f"\n{label}: longitud {len(bytes_data)} > {new_len}. Se truncara.")
        bytes_data = bytes_data[:new_len]
    elif len(bytes_data) < new_len:
        print(f"\n{label}: longitud {len(bytes_data)} < {new_len}. Se completara con bytes aleatorios.")
        needed_size = new_len - len(bytes_data)
        pad_bytes = get_random_bytes(needed_size)
        bytes_data += pad_bytes

    print(f"{label} ajustado ({new_len} bytes, HEX): {bytes_data.hex()}")
    return bytes_data


def bytes_b64(input: bytes) -> str:
    return base64.b64encode(input).decode('utf-8')


def encrypt_des_cbc(text: str, key: bytes, iv: bytes) -> bytes:
    cipher = DES.new(key, DES.MODE_CBC, iv)
    text_padded = pad(text.encode('utf-8'), 8)
    return cipher.encrypt(text_padded)


def decrypt_des_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> str:
    cipher = DES.new(key, DES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)
    return unpad(decrypted, 8).decode('utf-8')


def encrypt_des3_cbc(text: str, key: bytes, iv: bytes) -> bytes:
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    text_padded = pad(text.encode('utf-8'), 8)
    return cipher.encrypt(text_padded)


def decrypt_des3_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> str:
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)
    return unpad(decrypted, 8).decode('utf-8')

def encrypt_aes256_cbc(text: str, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    text_padded = pad(text.encode('utf-8'), 16)
    return cipher.encrypt(text_padded)


def decrypt_aes256_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> str:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)
    return unpad(decrypted, 16).decode('utf-8')

def main():
    print("=== Cifrado simetrico (CBC) ===")
    print("1. DES")
    print("2. 3DES")
    print("3. AES-256")

    choice = input("Seleccione el algoritmo (1/2/3): ").strip()
    texto = input("\nIngrese el texto a cifrar: ")

    if choice == "1":
        print("\n--- DES ---")
        key = input("Ingrese la llave (8 bytes max.): ")
        iv = input("Ingrese el IV (8 caracteres): ")

        key_bytes = normalize_bytes(key, 8, "Llave")
        iv_bytes = normalize_bytes(iv, 8, "IV")

        cipher = encrypt_des_cbc(texto, key_bytes, iv_bytes)
        print(f"\nTexto cifrado (Base64): {bytes_b64(cipher)}")
        print(f"Texto descifrado: {decrypt_des_cbc(cipher, key_bytes, iv_bytes)}")

    elif choice == "2":
        print("\n--- 3DES ---")
        k1 = input("Ingrese la llave 1 (8 bytes max.): ")
        k2 = input("Ingrese la llave 2 (8 bytes max.): ")
        k3 = input("Ingrese la llave 3 (8 bytes max.): ")
        iv = input("Ingrese el IV (8 caracteres): ")

        iv_bytes = normalize_bytes(iv, 8, "IV")
        key = (
            normalize_bytes(k1, 8, "Llave 1")
            + normalize_bytes(k2, 8, "Llave 2")
            + normalize_bytes(k3, 8, "Llave 3")
        )
        print(f"\nLlave combinada (24 bytes, HEX): {key.hex()}")

        cipher = encrypt_des3_cbc(texto, key, iv_bytes)
        print(f"\nTexto cifrado (Base64): {bytes_b64(cipher)}")
        print(f"Texto descifrado: {decrypt_des3_cbc(cipher, key, iv_bytes)}")

    elif choice == "3":
        print("\n--- AES-256 ---")
        key = input("Ingrese la llave (32 bytes max.): ")
        iv = input("Ingrese el IV (16 caracteres): ")

        key_bytes = normalize_bytes(key, 32, "Llave")
        iv_bytes = normalize_bytes(iv, 16, "IV")

        cipher = encrypt_aes256_cbc(texto, key_bytes, iv_bytes)
        print(f"\nTexto cifrado (Base64): {bytes_b64(cipher)}")
        print(f"Texto descifrado: {decrypt_aes256_cbc(cipher, key_bytes, iv_bytes)}")

    else:
        print("Opción no valida.")

if __name__ == "__main__":
    main()
