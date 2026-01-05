import socket
import ast
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding,serialization
from cryptography.hazmat.primitives.asymmetric import rsa


# Configuración del servidor de contenidos
servidor_contenidos_ip = '127.0.0.1'
servidor_contenidos_puerto = 8888

# Configuración del servidor de licencias
servidor_licencias_ip = '127.0.0.1'
servidor_licencias_puerto = 8889

# Configuración del CDM
cdm_ip = '127.0.0.1'
cdm_puerto = 8887

#############################################################
#           Funciones básicas del programa
#############################################################

def verificar_cifrado(contenido):
    """
    Función para verificar si el contenido está cifrado.
    """
    # Comprobar si el contenido tiene un encabezado específico,
    return contenido.startswith("ENCRYPTED:")

def recibir_contenido():
    """
    Función para recibir contenido del servidor de contenidos.
    """
    
    cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cliente.connect((servidor_contenidos_ip, servidor_contenidos_puerto))
    print("Conectado al servidor de contenidos.")
    
    # Pedir al usuario que elija un archivo para descargar
    print("Tips: si quieres solicitar la lista de contenidos, introduce 'list'.")
    print("Tips: si el archivo es grande, puede tardar unos minutos para la descarga.")
    
    tipo = None
    contenido = None
    archivo = None
    
    while True:
        archivo = input("Introduce el nombre del archivo que deseas descargar: ")
    
        if archivo=="list":
            # Solicitar la lista de contenidos disponibles
            cliente.sendall(b"list")
            
            # Recibir la lista de contenidos disponibles
            lista_contenidos = cliente.recv(10000).decode()
            print("\n")
            print(lista_contenidos)
        
        elif archivo=="fin":
            cliente.sendall(b"fin")
            cliente.close()
            exit(0)
        
        else:
            # Enviar la solicitud para descargar el archivo seleccionado
            cliente.sendall(b"enviar " + archivo.encode())
            
            # Recibir tipo del contenido (y si está cifrado)
            tipo = cliente.recv(10000).decode()

            if tipo != 'ERROR':  # Si se recibe contenido válido, proceder
                es_cifrado = verificar_cifrado(tipo)
                
                if es_cifrado:
                    # Recibir tamaño del contenido
                    size_data = cliente.recv(10000).decode()  # Recibir tamaño como string
                    contenido_tamano = int(size_data)  # Convertir a entero
                    
                    # Recibir el contenido completo en fragmentos
                    contenido = b""
                    recibido = 0
                    while recibido < contenido_tamano:
                        fragmento = cliente.recv(10000)  # Recibir en bloques
                        if not fragmento:
                            break
                        contenido += fragmento
                        recibido += len(fragmento)                    
                else:
                    contenido = cliente.recv(10000000).decode()
                    
                # Procesar contenido según si está cifrado
                if es_cifrado:
                    return True, contenido, tipo[len("ENCRYPTED:"):], archivo
                else:
                    return False, contenido, tipo, archivo

            else:
                print("No se pudo descargar el archivo. Intenta nuevamente.")
    
    return None

def recibir_clave_RSA(ip_destino,puerto_destino):
    """
    Envía la clave pública al receptor y recibe la clave e IV cifrados.
    Descifra la clave e IV utilizando la clave privada RSA.
    """
    
    # e,n: clave pública
    #   d: clave privada
    e,n,d = generar_claves_rsa()
    
    cliente.connect((ip_destino, puerto_destino))
    
    if (puerto_destino == 8887):
        print("Conectado al CDM.")
    if (puerto_destino == 8888):
        print("Conectado al servidor de contenidos.")
    if (puerto_destino == 8889):
        print("Conectado al servidor de licencias.")
    
    # Enviar los componentes de la clave pública
    clave_publica_serializada = "{0},{1}".format(e,n)
#     print("CLAVE RSA ENVIADA:",clave_publica_serializada)
    cliente.sendall(clave_publica_serializada.encode())
    
    # Recibir la clave e IV para comunicacion (cifrada con RSA)
    clave_comunicacion_cifrada = cliente.recv(10000).decode()
#     print(clave_comunicacion_cifrada)
    iv_comunicacion_cifrado = cliente.recv(10000).decode()
#     print(iv_comunicacion_cifrado)
    
    # Conversión de string "[1,2,3]" a lista [1,2,3]
    clave_comunicacion_cifrada= ast.literal_eval(clave_comunicacion_cifrada)
    iv_comunicacion_cifrado= ast.literal_eval(iv_comunicacion_cifrado)
    
    # Descifrar la clave e IV usando la clave privada
    clave_comunicacion = descifrar_rsa_bytes(clave_comunicacion_cifrada, d, n)
    iv_comunicacion = descifrar_rsa_bytes(iv_comunicacion_cifrado, d, n)
    
    return clave_comunicacion,iv_comunicacion

def pedir_licencia_CDM(licencia_deseada):
    """
    Función para pedir la solicitud de licencia al cdm.
    """
    cdm_key, cdm_iv = recibir_clave_RSA(cdm_ip,cdm_puerto)
    
    # Pedir solicitud para licencia del contenido deseado
    cliente.sendall(encriptar_texto(licencia_deseada.encode(), cdm_key, cdm_iv)) # Mensaje en bytes
    
    # Recibir la solicitud de licencia
    solicitud_licencia_enc = cliente.recv(100000000)
    solicitud_licencia = desencriptar_texto(solicitud_licencia_enc, cdm_key, cdm_iv).decode()
#     print(solicitud_licencia)
    
    # Recibir la clave pública del CDM
    k_pu_cdm_enc = cliente.recv(10000)
    k_pu_cdm = desencriptar_texto(k_pu_cdm_enc, cdm_key, cdm_iv).decode()
    print(f"Solicitud de licencia para '{licencia_deseada}' adquirida.")

    return solicitud_licencia,k_pu_cdm


def pedir_licencia_servidor(solicitud_licencia,clave_publica_cdm):
    """
    Función para pedir la licencia al servidor de licencias usando la solicitud del CDM.
    """
    licencias_key, licencias_iv = recibir_clave_RSA(servidor_licencias_ip,servidor_licencias_puerto)

#     print(solicitud_licencia)
    
    # Solicitud de licencia al servidor
    cliente.sendall(encriptar_texto(solicitud_licencia.encode(), licencias_key, licencias_iv)) # Mensaje en bytes
    cliente.sendall(encriptar_texto(clave_publica_cdm.encode(), licencias_key, licencias_iv)) # Mensaje en bytes

    # Recibir la licencia
    clave_contenido_enc = cliente.recv(10000)
    clave_contenido = desencriptar_texto(clave_contenido_enc, licencias_key, licencias_iv).decode()
    iv_contenido_enc = cliente.recv(10000)
    iv_contenido = desencriptar_texto(iv_contenido_enc, licencias_key, licencias_iv).decode()
    print(f"Clave adquirida del servidor de licencias.")
    
    licencia = "{0},{1}".format(clave_contenido,iv_contenido)
#     print(licencia)

    return licencia

def descifrar_contenido_CDM(licencia,contenido_cifrado):
    """
    Función para pedir al CDM que descifre el contenido con la licencia proporcionada.
    """
    cdm_key, cdm_iv = recibir_clave_RSA(cdm_ip,cdm_puerto)

    # Enviar licencia al CDM
    cliente.sendall(encriptar_texto(licencia.encode(), cdm_key, cdm_iv)) # Mensaje en bytes

    # Enviar la longitud del contenido
    longitud= str(len(contenido_cifrado)).encode()
    
    cliente.sendall(encriptar_texto(longitud, cdm_key, cdm_iv))

    # Enviar contenido cifrado
    cliente.sendall(encriptar_texto(contenido_cifrado, cdm_key, cdm_iv)) # Mensaje en bytes

    # Recibir contenido descifrado
    
    # Recibir tamaño del contenido
    size_data_enc = cliente.recv(10000)  # Recibir tamaño como string
    size_data= desencriptar_texto(size_data_enc, cdm_key, cdm_iv).decode()
    contenido_tamano = int(size_data)  # Convertir a entero
    
    # Recibir el contenido completo en fragmentos
    contenido_enc = b""
    recibido = 0
    while recibido < contenido_tamano:
        fragmento = cliente.recv(10000)  # Recibir en bloques
        if not fragmento:
            break
        contenido_enc += fragmento
        recibido += len(fragmento)
    
    contenido_descifrado = desencriptar_texto(contenido_enc, cdm_key, cdm_iv)
    print(f"Contenido descifrado por CDM con éxito.")
    
    return contenido_descifrado


#############################################################
#         Funciones relacionados con cifrado RSA
#############################################################

def descifrar_rsa_bytes(mensaje_cifrado, d, n):
    """
    Descifra un mensaje cifrado usando la clave privada RSA.
    """
    # Descifrar cada entero del mensaje cifrado y convertirlo a bytes
    mensaje_descifrado = bytes([pow(byte, d, n) for byte in mensaje_cifrado])
    return mensaje_descifrado

def generar_claves_rsa():
    """
    Genera un par de claves RSA usando la librería cryptography.
    Retorna la clave pública y privada, junto con los componentes (e, n).
    """    
    # Generar clave privada
    clave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    # Obtener clave pública
    clave_publica = clave_privada.public_key()
    
    # Extraer componentes de la clave pública
    numeros_publicos = clave_publica.public_numbers()
    e = numeros_publicos.e
    n = numeros_publicos.n
    
    numeros_privados = clave_privada.private_numbers()
    d = numeros_privados.d
    
    return (e, n, d)


#############################################################
#      Funciones relacionados con cifrado AES en modo CBC
#############################################################

def encriptar_texto(texto, clave, iv):
    """
    Cifra un texto utilizando AES en modo CBC con relleno PKCS7.

    Args:
        texto (bytes): El texto a cifrar.
        clave (bytes): La clave de cifrado (16 bytes).
        iv (bytes): El vector de inicialización (16 bytes).

    Returns:
        bytes: El texto cifrado.
    """
    cipher = Cipher(algorithms.AES(clave), modes.CBC(iv))
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(texto) + padder.finalize()

    return encryptor.update(padded_data)

def desencriptar_texto(texto_cifrado, clave, iv):
    """
    Descifra un texto cifrado utilizando AES en modo CBC y elimina el relleno PKCS7.

    Args:
        texto_cifrado (bytes): El texto cifrado.
        clave (bytes): La clave de cifrado (16 bytes).
        iv (bytes): El vector de inicialización (16 bytes).

    Returns:
        bytes: El texto descifrado sin relleno.
    """
    cipher = Cipher(algorithms.AES(clave), modes.CBC(iv))
    decryptor = cipher.decryptor()

    decipher_result = decryptor.update(texto_cifrado)

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(decipher_result) + unpadder.finalize()


#############################################################
#         Funciones para transformar contenidos
#############################################################

# Convertir un string de contenido a imagen
def string_to_image(image_string, output_path):
    image_data = base64.b64decode(image_string.encode("utf-8"))
    with open(output_path, "wb") as image_file:
        image_file.write(image_data)

# Convertir un string de contenido a video
def string_to_video(video_string, output_path):
    video_data = base64.b64decode(video_string.encode("utf-8"))
    with open(output_path, "wb") as video_file:
        video_file.write(video_data)


#############################################################
#     FASE 1: Comunicación con servidor de contenidos
#############################################################

ide,contenido,tipo,archivo = recibir_contenido()


#############################################################
#     FASE 2: Comunicación con CDM
#############################################################

# Verificar si el contenido está cifrado
# En cuyo caso, pedir al CDM una solicitud de licencia para el servidor de licencias
if ide:
    # Socket de la UA
    cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    solicitud_licencia, clave_publica_cdm = pedir_licencia_CDM(archivo)
    cliente.close()

    #############################################################
    #     FASE 3: Comunicación con servidor de licencias
    #############################################################
    
    # Socket de la UA
    cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Conexión con el servidor de licencias
    licencia = pedir_licencia_servidor(solicitud_licencia,clave_publica_cdm)
    cliente.close()


    #############################################################
    #     FASE 4: Descifrado del contenido desde CDM
    #############################################################
    
    # Socket de la UA
    cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Conexión con el CDM para obtener el contenido descifrado
    contenido_descifrado = descifrar_contenido_CDM(licencia,contenido).decode()
    print(f"'{archivo}' descifrado y almacenado con éxito en el equipo.")
    cliente.close()
    
    # Guardar contenido
    if tipo=="IMG":
        string_to_image(contenido_descifrado, "descarga/"+archivo)
    else:
        string_to_video(contenido_descifrado, "descarga/"+archivo)

else:
    # Guardar contenido
    if tipo=="IMG":
        string_to_image(contenido, "descarga/"+archivo)

    else:
        string_to_video(contenido, "descarga/"+archivo)

    