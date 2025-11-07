from PIL import Image
import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

# This is our secret marker. It MUST be identical in all functions.
EOF_MARKER = "!!!STOP!!!".encode('utf-8')
SALT_SIZE = 16 # We will generate a 16-byte random salt

# --- 1. CRYPTOGRAPHY FUNCTIONS (FIX IS IN HERE) ---

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derives a secure 32-byte encryption key from a password and salt.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))

def encrypt_data(data: bytes, password: str) -> bytes:
    """
    Encrypts data using the password. Generates a new salt.
    Returns: salt + encrypted_data
    """
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    f = Fernet(key)
    encrypted_data = f.encrypt(data)
    return salt + encrypted_data

def decrypt_data(data: bytearray, password: str) -> bytes: # <-- Takes in bytearray
    """
    Decrypts data using the password. Extracts the salt from the data.
    """
    try:
        # --- THIS IS THE FIX ---
        # We must convert the bytearray slices back to 'bytes'
        salt = bytes(data[:SALT_SIZE])
        encrypted_data_bytes = bytes(data[SALT_SIZE:])
        # --- END OF FIX ---
        
        key = derive_key(password, salt)
        f = Fernet(key)
        
        # This will fail and raise an exception if the password is wrong
        decrypted_data = f.decrypt(encrypted_data_bytes)
        return decrypted_data
    except Exception as e:
        print(f"Decryption failed (Wrong password or corrupt data): {e}")
        return None

# --- 2. STEGANOGRAPHY FUNCTIONS (NO CHANGES) ---

def get_secret_bit_stream(file_path, password):
    """
    Reads, ENCRYPTS, and converts a file into a stream of bits.
    """
    bit_stream = ""
    
    try:
        with open(file_path, 'rb') as f:
            secret_data = f.read()
    except Exception as e:
        print(f"Error reading secret file: {e}")
        return None

    try:
        encrypted_data = encrypt_data(secret_data, password)
    except Exception as e:
        print(f"Encryption failed: {e}")
        return None

    data_to_hide = encrypted_data + EOF_MARKER
    
    for byte in data_to_hide:
        bits = format(byte, '08b')
        bit_stream += bits
        
    print(f"File encrypted and converted to {len(bit_stream)} bits.")
    return bit_stream

def check_image_capacity(image_path, bits_to_hide):
    """
    Checks if the cover image has enough pixels to hide the data.
    """
    try:
        with Image.open(image_path) as img:
            width, height = img.size
        total_capacity = width * height * 3
        print(f"Image capacity: {total_capacity} bits")
        return total_capacity >= bits_to_hide
    except Exception as e:
        print(f"Error checking image capacity: {e}")
        return False

def hide_data_in_image(image_path, secret_bit_stream, save_path):
    """
    Hides the secret bit stream into the cover image and saves it.
    """
    try:
        with Image.open(image_path) as img:
            img = img.convert("RGBA")
            pixels = img.load()
            width, height = img.size
            
            bit_index = 0
            total_bits = len(secret_bit_stream)
            
            for y in range(height):
                for x in range(width):
                    r, g, b, a = pixels[x, y]
                    
                    if bit_index < total_bits:
                        # (r & 0xFE) clears the last bit. | int(...) sets it.
                        r = (r & 0xFE) | int(secret_bit_stream[bit_index])
                        bit_index += 1
                    
                    if bit_index < total_bits:
                        g = (g & 0xFE) | int(secret_bit_stream[bit_index])
                        bit_index += 1
                        
                    if bit_index < total_bits:
                        b = (b & 0xFE) | int(secret_bit_stream[bit_index])
                        bit_index += 1
                    
                    pixels[x, y] = (r, g, b, a)
                    
                    if bit_index >= total_bits: break
                if bit_index >= total_bits: break
            
            img.save(save_path, "PNG")
            print(f"Successfully hid {total_bits} bits in '{save_path}'")
            return True

    except Exception as e:
        print(f"Error hiding data in image: {e}")
        return False

def extract_data_from_image(image_path, save_path, password):
    """
    Extracts, DECRYPTS, and saves a hidden file from an image.
    """
    try:
        with Image.open(image_path) as img:
            img = img.convert("RGBA")
            pixels = img.load()
            width, height = img.size
            
            bit_stream = ""
            byte_array = bytearray()
            
            for y in range(height):
                for x in range(width):
                    
                    r, g, b, a = pixels[x, y]
                    
                    bit_stream += str(r & 1)
                    bit_stream += str(g & 1)
                    bit_stream += str(b & 1)
                    
                    while len(bit_stream) >= 8:
                        byte_str = bit_stream[:8]
                        bit_stream = bit_stream[8:]
                        byte_array.append(int(byte_str, 2))
                        
                        if byte_array.endswith(EOF_MARKER):
                            print("Found EOF marker!")
                            
                            encrypted_data = byte_array[:-len(EOF_MARKER)]
                            
                            print("Decrypting data...")
                            decrypted_data = decrypt_data(encrypted_data, password)
                            
                            if decrypted_data is None:
                                print("Decryption failed. Wrong password.")
                                return "password_error"
                            
                            with open(save_path, 'wb') as f:
                                f.write(decrypted_data)
                            
                            print(f"Successfully extracted file to '{save_path}'")
                            return "success"
            
            print("Error: Could not find EOF marker in image.")
            return "no_marker"

    except Exception as e:
        print(f"Error extracting data: {e}")
        return "error"