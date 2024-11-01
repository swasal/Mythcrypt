"""
A reference of how to use click commands with click shell

"""



import click
from click_shell import shell
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    # ... handle key storage

@click.command()
def generate_keys_cmd():
    generate_keys()

@shell(prompt='rsa-shell > ', intro='Welcome to the RSA shell!')
def my_shell():
    pass

my_shell.add_command(generate_keys_cmd)

if __name__ == '__main__':
    my_shell()
