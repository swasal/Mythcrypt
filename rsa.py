#imports
import os
import time
import datetime
import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM





# - - - - - - - - - - Key Generation - - - - - - - - - - 

def generate_key_pair(key_size=4096):
  """
  Generates an RSA public-private key pair.

  Args:
      key_size (int, optional): Length of the RSA key in bits. 
          Recommended values are 2048, 3072, or 4096. Defaults to 4096.

  Returns:
      Tuple[RSAPrivateKey, RSAPublicKey]: A tuple containing the generated 
      private key and corresponding public key.

  Example:
      private_key, public_key = generate_key_pair(2048)
  """

  private_key=rsa.generate_private_key(
      public_exponent=65537,
      key_size=key_size,
      backend=default_backend()
  )

  public_key=private_key.public_key()

  return private_key, public_key



def save_key_pair(private_key, public_key, path):
  """
  Saves an RSA key pair to PEM-formatted files in a timestamped folder.

  This function creates a subdirectory under the given path named 
  "Rsa keypair_<timestamp>", and writes the private key, public key, 
  and a plaintext info file describing the contents.

  Args:
      private_key (RSAPrivateKey): The RSA private key to save.
      public_key (RSAPublicKey): The RSA public key to save.
      path (str): The directory in which to create the key pair folder.

  Returns:
      str: The full path to the directory where the key files were saved.

  Example:
      save_path = save_key_pair(private_key, public_key, "./keys")

  Warning:
      The private key is saved unencrypted. Handle with extreme caution 
      and avoid exposing the saved files to untrusted environments.
  """
  x=str(round(int(time.time()),0))

  os.makedirs(os.path.join(path,f"Rsa keypair_{x}"))
  path=os.path.join(path,f"Rsa keypair_{x}") 
  
  private_key_path=os.path.join(path, 'private_key.pem')
  public_key_path=os.path.join(path, 'public_key.pem')
  info=os.path.join(path, 'info.txt')

  with open(private_key_path, 'wb') as f:
      f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))


  with open(public_key_path, 'wb') as f:
    f.write(public_key.public_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

  with open(info, "w") as f:
    s=f"""The folder contains an unencrypted 4096-bit RSA key pair.
Exercise extreme caution in safeguarding these keys.

The keys were made on {datetime.datetime.now().strftime("%Y-%m-%d%H:%M:%S")}
Unix timestamp: {x}
"""
    f.write(s)

  return path




def save_key(name, key, path, private=None):
  """
  Saves an RSA key (private or public) to a PEM file.

  The key is saved in PEM format to the specified path using the provided name.
  If `private` is truthy, the key is treated as a private key; otherwise, it is
  saved as a public key.

  Args:
      name (str): Base name for the saved key file (without extension).
      key (RSAPrivateKey or RSAPublicKey): The RSA key to save.
      path (str): Directory in which to save the key file.
      private (bool, optional): If True, saves the key as a private key.
          If False or None, saves it as a public key.

  Returns:
      str: The full path to the saved key file.

  Example:
      save_key("mykey", private_key, "./keys", private=True)
      save_key("mykey", public_key, "./keys")
  """
  name=name+".pem"

  if private:
    private_key_path=os.path.join(path, name)

    with open(private_key_path, 'wb') as f:
      f.write(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))
  
    return private_key_path
  # If private is not specified, save as public key
      
  else:  
    public_key_path=os.path.join(path, name)

    with open(public_key_path, 'wb') as f:
      f.write(key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
      ))

    return public_key_path






def newkeys(path=None):
  """
  Generates a new RSA key pair and saves them to disk.

  This function creates a 4096-bit RSA key pair, saves them in a
  timestamped folder, and prints the path to that folder.

  Args:
      path (str, optional): The directory in which to save the keys. 
          If None, keys are saved in the current working directory.

  Returns:
      str: The full path to the directory where the key pair was saved.

  Example:
      >>> key_dir = newkeys("./keys")
      >>> print("Keys saved to:", key_dir)
  """

  private_key, public_key=generate_key_pair()
  path=save_key_pair(private_key, public_key,path)
  print(path)
  return path





# - - - - - - - - - - Regenerating public key - - - - - - - - - - 

def get_public_key(private_key_path, filename):
  """
  Extracts the public key from a private key file and saves it as a PEM file.

  This function loads a private RSA key from the specified file, derives the
  corresponding public key, and saves it to a new PEM file in the same directory.

  Args:
      private_key_path (str): The path to the PEM-encoded private key file.
      filename (str): The desired name (without extension) for the saved public key file.

  Returns:
      str: The full path to the saved public key file.

  Example:
      >>> pubkey_path = get_public_key("keys/private_key.pem", "public_key")
      >>> print("Public key saved at:", pubkey_path)
  """

  with open(private_key_path, 'rb') as key_file:
    private_key=serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )

  public_key=private_key.public_key()
  
  path= os.path.dirname(private_key_path)
  path=save_key(filename, public_key, path, private=False)
  return path








def load_private(pem_file_path, password=None):
    with open(pem_file_path, "rb") as pem_file:
        private_key=serialization.load_pem_private_key(
            pem_file.read(),
            password=password,  # If your private key is encrypted, provide the password here.
            backend=default_backend()
        )
    return private_key



def load_public(pem_file_path):
    with open(pem_file_path, "rb") as pem_file:
        public_key=serialization.load_pem_public_key(
            pem_file.read(),
            backend=default_backend()
        )
    return public_key



def loadmessage(message_fileapth):
  messagefile=open(message_fileapth, "r")
  rawmessage=messagefile.readlines()
  message=""
  for i in rawmessage:
      message+=i

  return message


#
def encrypt_rsa(message, public_key):
  if isinstance(message, bytes):
      message_bytes = message
  else:
      message_bytes=message.encode('utf-8')
  """Encrypts a message in plain english using the public key."""
  return public_key.encrypt(
      message_bytes,
      padding.OAEP(
          mgf=padding.MGF1(algorithm=hashes.SHA256()),
          algorithm=hashes.SHA256(),
          label=None
      )
  )



def decrypt_rsa(ciphertext, private_key):
  """Decrypts a message using the private key."""
  ciphertext=private_key.decrypt(
      ciphertext,
      padding.OAEP(
          mgf=padding.MGF1(algorithm=hashes.SHA256()),
          algorithm=hashes.SHA256(),
          label=None
      )
  )

  return ciphertext



def encryptfile(filepath, public_key):
  """
  Encrypts a file's contents using AES-256 (GCM) and encrypts the AES key with RSA.

  This function reads the contents of a file, encrypts the data with AES-256-GCM 
  using a randomly generated key and IV, and then encrypts the key, IV, and file 
  extension using the provided RSA public key. It also generates a fingerprint 
  of the public key for verification during decryption.

  Args:
      filepath (str): The path to the file that will be encrypted.
      public_key (RSAPublicKey): The RSA public key used to encrypt the AES key and metadata.

  Returns:
      dict or bool: A dictionary containing the encrypted data and metadata
      (such as fingerprint, encrypted key/IV, ciphertext, etc.), or False if the file is empty.

  Returned Dictionary Structure:
      {
          'magic': "Mythcrypt",                 # Identifier for format validation
          'version': '0.1.0',                   # Version of the encryption schema
          'fingerprint': <SHA-256 of public key>,
          'timestamp': <UNIX timestamp>,
          'key': <hex-encoded RSA-encrypted AES key>,
          'iv': <hex-encoded RSA-encrypted IV>,
          'fileformat': <hex-encoded RSA-encrypted file extension>,
          'ciphertext': <base64-encoded ciphertext>,
          'tag': <hex-encoded GCM authentication tag>
      }

  Raises:
      FileNotFoundError: If the file at `filepath` does not exist.

  Example:
      >>> enc = encryptfile("secret.txt", public_key)
      >>> with open("secret.scroll", "w") as f:
      ...     json.dump(enc, f, indent=4)
  """

  # generate a fingerprint of the key 
  
  public_bytes = public_key.public_bytes(
      encoding=serialization.Encoding.DER,
      format=serialization.PublicFormat.SubjectPublicKeyInfo
  )
  
  digest = hashes.Hash(hashes.SHA256())
  digest.update(public_bytes)
  fingerprint_bytes = digest.finalize()
  fingerprint_hex = fingerprint_bytes.hex()

  # read the file data
  with open(filepath, 'rb') as file:
    data = file.read()
  # Check if the file is empty
  if not data:  
    print("The file is empty. No data to encrypt.")
    return False
  
  # get the fileformat
  fileformat = os.path.splitext(filepath)[1][1:]  # Get the file extension without the dot
  if not fileformat:
    fileformat = None  # Default to JNone if no extension is found

  # generate an IV
  iv = os.urandom(12) #12 byte IV generation
  # generate a key 
  key = os.urandom(32) # 32 bytes for AES-256

  # generate an aesgcm object use it to encrypt the data
  aesgcm = AESGCM(key)
  ciphertext_and_auth = aesgcm.encrypt(iv, data, None)

  # extract the ciphertext and authentication tag
  ciphertext = ciphertext_and_auth[:-16]  # Last 16 bytes are the tag
  tag = ciphertext_and_auth[-16:]  # Last 16 bytes are the tag
  
  #encrypt the key and IV and fileformat
  encrypted_key = encrypt_rsa(key, public_key)
  encrypted_iv = encrypt_rsa(iv, public_key)
  if fileformat!=None: 
    encrypted_fileformat = encrypt_rsa(fileformat, public_key)
  else:
    encrypted_fileformat = encrypt_rsa("None", public_key)

  #return the encrypted key, IV, ciphertext and tag
  return {
      'magic': "Mythcrypt",
      'version': '0.1.0',
      'fingerprint': fingerprint_hex,
      'timestamp': int(time.time()),
      'key': encrypted_key.hex(),
      'iv': encrypted_iv.hex(),
      'fileformat': encrypted_fileformat.hex(),
      'ciphertext': base64.b64encode(ciphertext).decode("utf-8"),
      'tag': tag.hex()
  }




def decryptfile(encrypted_data, private_key):
  """
  Decrypts AES-encrypted file data using a provided RSA private key.

  This function verifies the metadata and fingerprint, decrypts the AES key, 
  IV, and file format using the RSA private key, and then uses the AES-GCM 
  algorithm to decrypt the ciphertext. It also verifies the integrity of the 
  encrypted data using the authentication tag.

  Args:
      encrypted_data (dict): The dictionary containing encrypted fields 
          generated by the `encryptfile()` function.
      private_key (RSAPrivateKey): The RSA private key used to decrypt 
          the AES key and associated metadata.

  Returns:
      tuple: A tuple `(databytes, fileformat)` where:
          - `databytes` (bytes): The decrypted content of the file.
          - `fileformat` (str): The original file extension (e.g., "txt").

      Returns `False` if verification fails or decryption is unsuccessful.
      Returns `"Invalid Tag Length"` if the tag size is incorrect.

  Raises:
      None directly, but logs any exception that occurs during decryption.

  Example:
      >>> with open("secret.scroll", "r") as f:
      ...     encrypted_data = json.load(f)
      >>> decrypted_data, ext = decryptfile(encrypted_data, private_key)
      >>> with open("recovered." + ext, "wb") as f:
      ...     f.write(decrypted_data)
  """

  # Validate the header
  if encrypted_data.get('magic') != "Mythcrypt":
      print("Invalid file format or version mismatch.")
      return False

  # Verify fingerprint
  public_key = private_key.public_key()
  public_bytes = public_key.public_bytes(
      encoding=serialization.Encoding.DER,
      format=serialization.PublicFormat.SubjectPublicKeyInfo
  )
  digest = hashes.Hash(hashes.SHA256())
  digest.update(public_bytes)
  fingerprint_hex = digest.finalize().hex()

  if encrypted_data.get('fingerprint') != fingerprint_hex:
      print("Fingerprint mismatch. The data cannot be decrypted with the private key provided.")
      return False
   
  # Decrypt the key and IV
  # Decrypt AES key, IV, and file format
  key = decrypt_rsa(bytes.fromhex(encrypted_data['key']), private_key)
  iv = decrypt_rsa(bytes.fromhex(encrypted_data['iv']), private_key)
  fileformat = decrypt_rsa(bytes.fromhex(encrypted_data['fileformat']), private_key).decode('utf-8')

   # Create AESGCM 
  aesgcm = AESGCM(key)
  ciphertext = base64.b64decode(encrypted_data['ciphertext'])
  tag = bytes.fromhex(encrypted_data['tag'])
  # Check if the tag is valid
  if len(tag) != 16:
      print("Invalid tag length. Expected 16 bytes.")
      return "Invalid Tag Length"
  try:
      # Decrypt (tag must be appended to ciphertext for AESGCM)
      databytes = aesgcm.decrypt(iv, ciphertext + tag, None)

      print("Decryption successful, data is authentic.")
      return databytes, fileformat

  except Exception as e:
      print("Decryption failed or data was tampered with:", str(e))
      return False
 

  






if __name__=='__main__':
  newkeys()