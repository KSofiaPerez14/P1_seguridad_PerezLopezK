import hashlib
from Crypto.Util.number import getPrime, inverse
import Crypto.Random


def leer_ultimo_bytes(filename, num_bytes):
    with open(filename, "rb") as f:
        f.seek(-num_bytes, 2)
        return f.read(num_bytes)


# Número de bits
bits = 1024

# Obtener los primos para Alice
pA = getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
qA = getPrime(bits, randfunc=Crypto.Random.get_random_bytes)

# Obtenemos la primera parte de la lave publica de alice
nA = pA * qA

# Calculamos la funcion phi de n
phiA = (pA - 1) * (qA - 1)
# Por razones de eficiencia utilizaremos el número 4 de Fermat, 65537, debido a que es
# un primo largo y no es potencia de 2, y como forma parte de la clave pública
# no  es necesario calcularlo
e = 65537

# Calculamos la clave privada de Alice
dA = inverse(e, phiA)

# Firma digital de Alice
with open("NDA.pdf", "rb") as f:
    pdf_bytes = f.read()
    pdf_h = int.from_bytes(hashlib.sha256(pdf_bytes).digest(), "big")
firma = pow(pdf_h, dA, nA)

num_bits=8
# Convertimos la firma a bytes
firma_bytes = firma.to_bytes((firma.bit_length() + (num_bits-1)) // num_bits, byteorder="big")

# lo agregamos al final del archivo pdf
with open("NDA.pdf", "ab") as f:
    f.write(firma_bytes)

# checamos los ultimos 256 bytes
bytes_firma_pdf_AC = leer_ultimo_bytes("NDA.pdf", 256)


#los convertimos a int
firma_int_de_pdf_AC = int.from_bytes(bytes_firma_pdf_AC, byteorder='big')

# quitamos la firma del archivo
with open("NDA.pdf", "rb") as f:
    pdf_bytes_AC = f.read()[:-256]
    pdf_h_AC = int.from_bytes(hashlib.sha256(pdf_bytes_AC).digest(), "big")

# Verificación por AC con la publica de Alice
firma_verificada_AC = pow(firma_int_de_pdf_AC, e, nA)
print("Firma verificada por AC:", firma_verificada_AC == pdf_h_AC)

#una vez esta verificado por AC, removemos la firma del archivo
with open("NDA.pdf", "wb") as f:
    f.write(pdf_bytes_AC)

# Obtener los primos para AC
pAC = getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
qAC = getPrime(bits, randfunc=Crypto.Random.get_random_bytes)

# Obtenemos la primera parte de la lave publica de AC
nAC = pAC * qAC

# Calculamos la funcion phi de n
phiAC = (pAC - 1) * (qAC - 1)

# Por razones de eficiencia utilizaremos el número 4 de Fermat, 65537, debido a que es
# un primo largo y no es potencia de 2, y como forma parte de la clave pública
# no  es necesario calcularlo
eAC = 65537

# Calculamos la clave privada de AC
dAC = inverse(eAC, phiAC)

# Firma de AC con la publica de AC
firma_AC = pow(pdf_h_AC, dAC, nAC)

# Agregamos la firma de AC al final del archivo
firma_AC_bytes = firma_AC.to_bytes(
    (firma_AC.bit_length() + (num_bits-1)) // num_bits, byteorder="big")
with open("NDA.pdf", "ab") as f:
    f.write(firma_AC_bytes)

# Verificación por Bob
# checamos los ultimos 256 bytes
firma_bytes_de_pdf_BOB = leer_ultimo_bytes("NDA.pdf", 256)
#los convertimos a int
firma_int_de_pdf_BOB = int.from_bytes(firma_bytes_de_pdf_BOB, byteorder='big')

# removemos la firma del archivo
with open("NDA.pdf", "rb") as f:
    pdf_bytes_BOB = f.read()[:-256]
    pdf_h_BOB = int.from_bytes(hashlib.sha256(pdf_bytes_BOB).digest(), "big")

pdf_h_verificada_bob = pow(firma_AC, eAC, nAC)
print("Firma verificada por Bob:", pdf_h_verificada_bob == pdf_h_AC)