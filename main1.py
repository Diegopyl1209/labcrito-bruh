import sys

def cesar(texto, desplazamiento):
    resultado = ""
    for caracter in texto:
        if caracter.isalpha():
            base = ord('A') if caracter.isupper() else ord('a')
            resultado += chr((ord(caracter) - base + desplazamiento) % 26 + base)
        else:
            resultado += caracter
    return resultado


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Uso: python script.py <texto> <desplazamiento>")
        sys.exit(1)

    text = sys.argv[1]
    desplazamiento = int(sys.argv[2])

    cifrado = cesar(text, desplazamiento)
    print(cifrado)
