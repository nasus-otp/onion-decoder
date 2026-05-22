import base64
import urllib.parse
import argparse
import html
import re
import codecs

def fix_base64_padding(s):
    """
    Corrige el padding de Base64 y Base64URL. 
    Reemplaza caracteres de URL safe y añade los '=' faltantes.
    """
    s = s.replace('-', '+').replace('_', '/')
    padding = len(s) % 4
    if padding:
        s += '=' * (4 - padding)
    return s

def decode_layer(text, target_word=None):
    """
    Intenta aplicar diferentes decodificadores. 
    Retorna: (Booleano_Exito, Nuevo_Dato, Nombre_Tecnica)
    """
    # 1. HTML Entities (Ej: &lt;script&gt;)
    if '&' in text and ';' in text:
        unescaped = html.unescape(text)
        if unescaped != text:
            return True, unescaped, "HTML Unescape"

    # 2. URL Decode (Ej: %3D%3D)
    if '%' in text:
        unquoted = urllib.parse.unquote(text)
        if unquoted != text:
            return True, unquoted, "URL Decode"

    # 3. Hexadecimal (Ej: 0x4142, \x41, o 4142)
    clean_hex = re.sub(r'(0x|\\x|\s)', '', text)
    if clean_hex and len(clean_hex) % 2 == 0 and re.match(r'^[0-9A-Fa-f]+$', clean_hex):
        try:
            decoded_bytes = bytes.fromhex(clean_hex)
            decoded_str = decoded_bytes.decode('utf-8')
            # Validamos que el resultado tenga sentido (caracteres imprimibles) 
            # para evitar que números normales sean interpretados como Hex.
            if decoded_str != text and decoded_str.isprintable():
                return True, decoded_str, "Hexadecimal Decode"
        except Exception:
            pass

    # 4. Binario a Texto (Ej: 01000001)
    clean_bin = re.sub(r'\s', '', text)
    if clean_bin and len(clean_bin) % 8 == 0 and re.match(r'^[01]+$', clean_bin):
        try:
            n = int(clean_bin, 2)
            decoded_bytes = n.to_bytes((len(clean_bin) + 7) // 8, byteorder='big')
            decoded_str = decoded_bytes.decode('utf-8')
            if decoded_str != text and decoded_str.isprintable():
                return True, decoded_str, "Binario a ASCII"
        except Exception:
            pass

    # 5. Base64 / Base64URL
    # Validamos que parezca Base64 mediante Regex para evitar falsos positivos
    if re.match(r'^[A-Za-z0-9+/_-]+={0,2}$', text.strip()) and len(text.strip()) >= 4:
        try:
            fixed_b64 = fix_base64_padding(text.strip())
            decoded_bytes = base64.b64decode(fixed_b64, validate=True)
            try:
                decoded_str = decoded_bytes.decode('utf-8')
                if decoded_str != text:
                    return True, decoded_str, "Base64 / Base64URL"
            except UnicodeDecodeError:
                # Manejo de Errores Silenciosos: Es Base64 válido, pero oculta un binario crudo
                # (ej. un ejecutable .exe, un payload de meterpreter, una imagen)
                return True, decoded_bytes, "Base64 (Bytes Crudos / Binario)"
        except Exception:
            pass
            
    # 6. ROT13 (Sustitución)
    # Solo lo aplicamos si hay target_word para evitar un bucle infinito (Rot13 x2 = Original)
    if target_word:
        try:
            rot13_str = codecs.encode(text, 'rot_13')
            if target_word in rot13_str:
                return True, rot13_str, "ROT13"
        except Exception:
            pass

    return False, text, ""

def auto_decode(encoded_text, target_word=None):
    print("[*] Iniciando motor de decodificación avanzada...\n")
    
    current_data = encoded_text
    layer = 1
    
    while True:
        # Mecanismo de seguridad: Si la capa anterior extrajo un binario, detenemos el script de texto
        if isinstance(current_data, bytes):
            print(f"\n[!] ALERTA: Se obtuvieron bytes crudos no legibles (no es texto UTF-8).")
            print("[!] Esto suele ser un binario ofuscado, un shellcode o un archivo.")
            break
            
        success, new_data, technique = decode_layer(current_data, target_word)
        
        if success:
            # Mostramos un fragmento de la nueva capa (preview) para no inundar la terminal
            preview = str(new_data)[:70] + "..." if len(str(new_data)) > 70 else str(new_data)
            print(f"[Capa {layer}] {technique} aplicado -> {preview}")
            
            current_data = new_data
            layer += 1
            
            if target_word and isinstance(current_data, str) and target_word in current_data:
                print(f"\n🚀 ¡Palabra clave '{target_word}' encontrada en la capa {layer-1}!")
                break
        else:
            print("\n[*] Fin del proceso. No se detectan más firmas de ofuscación conocidas.")
            break
            
    return current_data

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Onion Decoder Pro: Herramienta de pentesting para desofuscar payloads multicapa.")
    parser.add_argument("-t", "--text", required=True, help="El texto/payload que deseas analizar")
    parser.add_argument("-w", "--word", help="Opcional: Palabra clave para detener la búsqueda (ej. admin, HTB{, SELECT)", default=None)
    
    args = parser.parse_args()
    
    resultado = auto_decode(args.text, args.word)
    
    print("\n=== EXTRACCIÓN FINAL ===")
    if isinstance(resultado, bytes):
        # Si extrajo un shellcode/binario, lo muestra en formato Hexadecimal forense
        print(f"[HEX DUMP] {resultado.hex()}")
    else:
        print(resultado)
    print("========================\n")
