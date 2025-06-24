#imports
import os
import time
import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend





# - - - - - - - - - - Key Generation - - - - - - - - - - 

def generate_key_pair(key_size=4096):
  """Generates an RSA key pair.

  Args:
    key_size: The size of the key in bits. Defaults to 2048.

  Returns:
    A tuple of (private_key, public_key).
  """

  private_key=rsa.generate_private_key(
      public_exponent=65537,
      key_size=key_size,
      backend=default_backend()
  )

  public_key=private_key.public_key()

  return private_key, public_key



def save_key_pair(private_key, public_key, path):
  """Saves the key pair to files.

  Args:
    private_key: The private key.
    public_key: The public key.
    path: path to save
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
  """Saves the keys to specific path.

  Args:
    private_key: The private key.
    public_key: The public key.
    path: path to save
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
  private_key, public_key=generate_key_pair()
  path=save_key_pair(private_key, public_key,path)
  print(path)
  return path





# - - - - - - - - - - Regenerating public key - - - - - - - - - - 

def get_public_key(private_key_path, filename):
  """Extracts the public key from a private key file.

  Args:
    private_key_path: Path to the private key file.

  Returns:
    The public key as a bytes object and saves it in the same dir as the privatekey.
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
def encrypt(message, public_key):
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



def encryptfile(message, public_key):
  """Encrypts a file using the public key."""
  return public_key.encrypt(
      message,
      padding.OAEP(
          mgf=padding.MGF1(algorithm=hashes.SHA256()),
          algorithm=hashes.SHA256(),
          label=None
      )
  )



def decrypt(ciphertext, private_key):
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






if __name__=='__main__':
  newkeys()