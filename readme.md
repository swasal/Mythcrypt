# Mythcrypt

**Mythcrypt** is a lightweight, open-source command-line tool designed for secure file encryption. Utilizing RSA encryption, Mythcrypt allows you to encrypt messages and files, generate and manage RSA key pairs keeping them safe from unauthorized access.

## Download

Latest version => ** [Download Mythcrypt Latest](https://github.com/swasal/Mythcrypt/releases/tag/v0.1.0)** 

** [Download Mythcrypt v0.1.0](https://github.com/swasal/Mythcrypt/releases/tag/v0.1.0)**  
Grab the latest stable release from the official GitHub Releases page.

## Features

- **RSA Encryption**: Encrypt and decrypt messages and files using RSA public and private keys.
- **Key Management**: Generate new RSA key pairs or derive a public key from an existing private key.
- **Command-Line Interface**: Interactive CLI built with `click` and `click_shell` for ease of use.

**rsa encryption can only encrypt small files trying to encrypt a large file would result in a value error**

## Getting Started

### Prerequisites

Ensure you have Python installed. Recommended python 3.13.0 butolder versions might work too. 

Then, install the required dependencies:

```bash
pip install -r requirements.txt
```

### Running Mythcrypt
Start the Mythcrypt CLI by executing:

```bash
python mythcrypt.py
```

You'll be greeted with the Mythcrypt console prompt:
```plaintext
Welcome to the Mythcrypt console [v 0.1.0].
Type "exit", "help", or "about" for more information.
mythcrypt >
```


## Usage
Within the Mythcrypt shell, you can use the following commands:

- **help**: Display available commands and their descriptions.
- **version**: Show the current version of Mythcrypt.
- **generatekeys**: Generate a new RSA public-private key pair.
- **generatepublic**: Generate a public key from an existing private key.
- **encrypt**: Encrypt a message using a public key.
- **encryptfile**: Encrypt a file using a public key.
- **decryptfile**: Decrypt a file using a private key.
- **exit**: Exit the Mythcrypt shell.

## Future Enhancements
Planned features for upcoming releases:

- **Session Key Support**: Implement hybrid AES + RSA encryption for enhanced security.
- **Key Validation Tools**: Verify the integrity and authenticity of RSA keys.
- **Metadata Encryption**: Embed and encrypt metadata within files.
- **Plugin System**: Allow community-developed plugins to extend Mythcrypt's functionality.


## Quick Start (Windows)

To run Mythcrypt easily from anywhere on your Windows system, you can create a batch file:
**Make sure the requirements.txt is installed globally in your machine**

```bat
@echo off
python PathToMythcryptDir\mythcrypt.py
```
Save this as mythcrypt.bat and place it in a folder that is included in your system's PATH environment variable. This way, you can simply open a command prompt and type:

```bash
mythcrypt
```

to launch the Mythcrypt console from any directory.

If you haven't added the folder containing mythcrypt.bat to your PATH, you can do so by editing your system environment variables.

Alternatively, you can run Mythcrypt directly by navigating to its directory and executing:

```bash
python mythcrypt.py
```




Thanks for checking out Mythcrypt!!

