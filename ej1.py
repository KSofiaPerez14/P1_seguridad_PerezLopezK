import hashlib
import Crypto.Util.number as n
import Crypto as c

# Número de bits
bits = 1024

# Obtener los primos para Alice y Bob
pA = n.getPrime(bits, randfunc=c.Random.get_random_bytes)
print("pA: ", pA, "\n")
qA = n.getPrime(bits, randfunc=c.Random.get_random_bytes)
print("qA: ", qA, "\n")

pB = n.getPrime(bits, randfunc=c.Random.get_random_bytes)
print("pB: ", pB, "\n")
qB = n.getPrime(bits, randfunc=c.Random.get_random_bytes)
print("qB: ", qB, "\n")

# Obtenemos la primera parte de la lave publica de alice and bob
nA = pA * qA
print("nA: ", nA, "\n")
nB = pB * qB
print("nB: ", nB, "\n")

# Calculamos la funcion phi de n
phiA = (pA - 1) * (qA - 1)
print("phiA: ", phiA, "\n")

phiB = (pB - 1) * (qB - 1)
print("phiB: ", phiB, "\n")

# Por razones de eficiencia utilizaremos el número 4 de Fermat, 65537, debido a que es
# un primo largo y no es potencia de 2, y como forma parte de la clave pública
# no  es necesario calcularlo
e = 65537

# Calculamos la clave privada de Alice y Bob
dA = n.inverse(e, phiA)
print("dA: ", dA, "\n")

dB = n.inverse(e, phiB)
print("dB: ", dB, "\n")

# Mensaje original
M="Un enfoque exitoso de ciberseguridad tiene múltiples capas de protección repartidas en las computadoras, redes, programas o datos que uno pretende mantener a salvo. En una organización, las personas, los procesos y la tecnología deben complementarse para crear una defensa eficaz contra los ciberataques. Un sistema unificado de gestión de amenazas puede automatizar las integraciones entre productos selectos de seguridad de Cisco y acelerar las funciones de operaciones de seguridad claves: detección, investigación y corrección.Los usuarios deben comprender y cumplir con los principios básicos de seguridad de datos, como elegir contraseñas seguras, ser cautelosos con los archivos adjuntos de los correos electrónicos y hacer copias de seguridad de datos. Obtenga más información sobre los principios básicos de ciberseguridad.Las organizaciones deben tener una estructura para manejar los ciberataques tentativos y sospechosos. Una estructura de buena reputación puede guiarlo y explicar cómo puede identificar ataques, proteger sistemas, detectar y responder a amenazas, y recuperarse de ataques exitosos. Vea la explicación en video del marco de ciberseguridad del NIST"# Longitud del mensaje original
print("Longitud de M:", len(M))

# Hash del mensaje original
h_M = hashlib.sha256(M.encode('utf-8')).hexdigest()
print("Hash de M:", h_M)

# Dividir mensaje en partes de 128 caracteres
parts = [M[i:i+128] for i in range(0, len(M), 128)]

# Cifrar partes con clave pública de Bob
encrypted_parts = []
for part in parts:
  c = pow(int.from_bytes(part.encode('utf-8'), byteorder='big'), e, nB)
  encrypted_parts.append(c)

# Descifrar partes con clave privada de Bob
decrypted_parts = []
for part in encrypted_parts:
  des = pow(part, dB, nB)
  decrypted_parts.append(des)

num_bits=8
# Reconstruir mensaje
M_prime = "".join([int.to_bytes(part, (part.bit_length() + (num_bits-1)) // num_bits, byteorder='big').decode('utf-8') for part in decrypted_parts])

# Hash del mensaje descifrado
h_M_prime = hashlib.sha256(M_prime.encode('utf-8')).hexdigest()
print("Hash de M':", h_M_prime)

# Comparar hashes
if h_M == h_M_prime:
  print("Los mensajes coinciden")
else:
  print("Los mensajes no coinciden")