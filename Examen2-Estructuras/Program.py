import heapq
from collections import Counter
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


class FNV1Hash:
    def __init__(self, bits=32):
        if bits == 32:
            self.FNV_prime = 16777619
            self.FNV_offset_basis = 2166136261
            self.mask = 0xFFFFFFFF
        elif bits == 64:
            self.FNV_prime = 1099511628211
            self.FNV_offset_basis = 14695981039346656037
            self.mask = 0xFFFFFFFFFFFFFFFF
        else:
            raise ValueError("FNV-1 solo soporta 32 o 64 bits")

    def hash(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')

        hash_value = self.FNV_offset_basis

        for byte in data:
            hash_value = (hash_value * self.FNV_prime) & self.mask
            hash_value = hash_value ^ byte

        return hash_value


fnv = FNV1Hash(32)

class Nodo:
    def __init__(self, char, freq):
        self.char = char
        self.freq = freq
        self.izq = None
        self.der = None

    def __lt__(self, otro):
        return self.freq < otro.freq


def construir_arbol_huffman(texto):
    if len(texto) == 1:
        return Nodo(texto, 1)

    frecuencia = Counter(texto)
    heap = [Nodo(char, freq) for char, freq in frecuencia.items()]
    heapq.heapify(heap)

    while len(heap) > 1:
        n1 = heapq.heappop(heap)
        n2 = heapq.heappop(heap)

        nuevo = Nodo(None, n1.freq + n2.freq)
        nuevo.izq = n1
        nuevo.der = n2

        heapq.heappush(heap, nuevo)

    return heap[0]


def generar_tabla_codigos(nodo, codigo="", tabla={}):
    if nodo.char is not None:
        tabla[nodo.char] = codigo
        return tabla

    generar_tabla_codigos(nodo.izq, codigo + "0", tabla)
    generar_tabla_codigos(nodo.der, codigo + "1", tabla)
    return tabla


def comprimir_huffman(texto):
    arbol = construir_arbol_huffman(texto)
    tabla = generar_tabla_codigos(arbol, "", {})
    comprimido = "".join(tabla[c] for c in texto)
    return comprimido, tabla, arbol


def descomprimir_huffman(bits, arbol):
    resultado = ""
    nodo = arbol
    for bit in bits:
        nodo = nodo.izq if bit == "0" else nodo.der
        if nodo.char is not None:
            resultado += nodo.char
            nodo = arbol
    return resultado



def generar_claves():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return public_key, private_key


def firmar_hash(valor_hash, private_key):
    hash_bytes = valor_hash.to_bytes(32, byteorder="big")

    firma = private_key.sign(
        hash_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return firma


def verificar_firma(valor_hash, firma, public_key):
    hash_bytes = valor_hash.to_bytes(32, byteorder="big")

    try:
        public_key.verify(
            firma,
            hash_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False


def menu():

    estado = {
        "mensaje": "",
        "hash_fnv": None,
        "comprimido": "",
        "tabla": None,
        "arbol": None,
        "public_key": None,
        "private_key": None,
        "firma": None
    }

    while True:
        print("\n----- MENÚ PRINCIPAL -----")
        print("1. Ingresar mensaje")
        print("2. Calcular hash FNV-1")
        print("3. Comprimir mensaje (Huffman)")
        print("4. Firmar hash con clave privada RSA")
        print("5. Simular envío")
        print("6. Descomprimir y verificar firma")
        print("7. Mostrar autenticidad")
        print("8. Salir")

        opcion = input("Seleccione opción: ")

        if opcion == "1":
            estado["mensaje"] = input("Ingrese su mensaje: ")

        elif opcion == "2":
            estado["hash_fnv"] = fnv.hash(estado["mensaje"])
            print("Hash FNV-1:", estado["hash_fnv"])

        elif opcion == "3":
            c, t, a = comprimir_huffman(estado["mensaje"])
            estado["comprimido"] = c
            estado["tabla"] = t
            estado["arbol"] = a

            print("Tamaño original:", len(estado["mensaje"]) * 8, "bits")
            print("Tamaño comprimido:", len(c), "bits")

        elif opcion == "4":
            estado["public_key"], estado["private_key"] = generar_claves()
            estado["firma"] = firmar_hash(estado["hash_fnv"], estado["private_key"])
            print("Firma generada correctamente.")

        elif opcion == "5":
            print("\n--- ENVÍO SIMULADO ---")
            print("Mensaje comprimido enviado.")
            print("Firma enviada.")
            print("Clave pública enviada.")
        elif opcion == "6":
            print("\n--- RECEPCIÓN DEL MENSAJE ---")

            recibido = descomprimir_huffman(estado["comprimido"], estado["arbol"])
            print("Mensaje recibido:", recibido)

            hash_rec = fnv.hash(recibido)

            valido = verificar_firma(hash_rec, estado["firma"], estado["public_key"])
            print("Firma válida." if valido else "Firma inválida.")

        elif opcion == "7":
            hash_rec = fnv.hash(estado["mensaje"])
            if verificar_firma(hash_rec, estado["firma"], estado["public_key"]):
                print("Mensaje auténtico y no modificado.")
            else:
                print("Mensaje alterado o firma no válida.")

        elif opcion == "8":
            break

        else:
            print("Opción inválida.")

menu()