# imports

# imports for shell
import sys
import datetime
import click
from click_shell import shell
from rich import print as rprint
from rich.console import Console
from rich.table import Table
import os
import rsa



#vars and innit

#global

v="v 0.1.0" #version

# mythcrypt_data = os.path.join(os.getenv("LOCALAPPDATA"), 'mythcrypt')



key={'public':None, 'private':None}

#innits
console= Console()



# shell start function
@shell(prompt="mythcrypt >", intro=f"""Welcome to the Mythcrypt console [{v}].
Your command-line companion for mythically secure file encryption.
Type "exit", "help", or "about" for more information. 
""")
def mythcrypt():
    rprint("[dim]Initializing shell...[/dim]")



#shell commands
@mythcrypt.command()
def help():
    """Displays help information for MythCrypt."""
    rprint(f"""
[bold cyan]Welcome to MythCrypt Help[/bold cyan]
[dim]Your command-line companion for mythically secure file encryption.[/dim]

[bold]Version:[/bold] [green]{v}[/green]

Use the commands below to interact with MythCrypt. Type a command and press [bold]Enter[/bold] to execute it.
""")

    table = Table(title="Available Commands", header_style="bold magenta", border_style="dim")
    table.add_column("Command", style="cyan", no_wrap=True)
    table.add_column("Description", style="white")

    table.add_row("help", "Show this help menu")
    table.add_row("version", "Display the current version of MythCrypt")
    table.add_row("generatekeys", "Generate a new RSA public-private key pair")
    table.add_row("generatepublic", "Generate a public key from a private key")
    table.add_row("encrypt", "Encrypt a message using a public key")
    table.add_row("encryptfile", "Encrypt a file using a public key")
    table.add_row("decryptfile", "Decrypt a file using a private key")
    table.add_row("devdata", "View internal developer diagnostics")
    table.add_row("exit", "Exit the MythCrypt shell")

    console.print(table)

    # Future Features
    rprint("""
[bold yellow]Coming Soon:[/bold yellow]
• [cyan]Session key support[/cyan] – Hybrid AES + RSA encryption
• [cyan]Secure password vault[/cyan] – Store secrets and credentials
• [cyan]Key validation tools[/cyan] – Verify key integrity and trust
• [cyan]Metadata encryption[/cyan] – Embed secure headers in your files
• [cyan]Web GUI[/cyan] – Drag-and-drop frontend for non-technical users
• [cyan]Plugin system[/cyan] – Extend MythCrypt via community tools

For full documentation and source code, visit:
[bold green][link=https://https://github.com/swasal/Mythcrypt]https://https://github.com/swasal/Mythcrypt[/link][/bold green]
""")   



@click.command()
def version():
    global v
    rprint(f"Current Mythcrypt version is =>[bold magenta]{v}[/bold magenta]")

mythcrypt.add_command(version)



@click.command()
@click.option("--path", "-p", type=click.Path(), help='Path to a file or directory.', prompt="Enter path to save key pair")
def generatekeys(path):
    if path=="None":
        path=None
    else:
        rprint(f"Path found\n")
    with console.status("Generating keys...\n", spinner="dots"):
        path=rsa.newkeys(path)
        rprint(f"[green]The keys have been generated succesfully[/green]\nThe keypair have been saved here => [magenta]{path}[/magenta]\n")

mythcrypt.add_command(generatekeys)



@click.command()
@click.option("--path", "-p", type=click.Path(), help='Path to a private key.', prompt="Enter private key path")
def generatepublic(path):
    if path=="None":
        rprint(f"[red]No path provided[/red]\n")
        sys.exit(1)
    else:
        rprint(f"Private key found\n")
    with console.status("Generating public key...\n", spinner="dots"):
        path=rsa.get_public_key(path)
        rprint(f"[green]The keys have been generated succesfully[/green]\nThe keypair have been saved here => [magenta]{path}[/magenta]\n")

mythcrypt.add_command(generatepublic)



@click.command()
@click.option("--key", "-k", type=click.Path(), help='Path to a file or directory.', prompt="Enter path to encryption(public) key")
@click.option("--message", "-m",help="The message to be encrypted using th4e provided key")
@click.option("--output", "-o",help="output file bool", default=f'ciphertext_{datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")}.enc')
def encryptmsg(key, message, output):
    #loading the key
    if os.path.exists(key):
        key=rsa.load_public(key)
    else: rprint(f"[red]Invalid key file[/red]")

    message=input("Enter message to be encrypted :")
    ciphetext=rsa.encrypt(message, key)

    #writes to a file
    with open(output,"wb") as f:
        f.write(ciphetext)
    if os.path.exists(output):
        rprint(f"The encrypted file have been saved here => [magenta]{output}[/magenta]")
    else: rprint(f"[red]There was an error in saving the file[/red]")
        
mythcrypt.add_command(encryptmsg)



@click.command()
@click.option("--key", "-k", type=click.Path(), help='Path to a file or directory.', prompt="Enter path to encryption(public) key")
@click.option("--filepath", "-f", help="The path to the file to be encrypted", prompt="Enter filepath of the file to encrypt")
def encryptfile(key, filepath):
    #loading the key
    if os.path.exists(key):
        key=rsa.load_public(key)
    else: rprint(f"[red]Invalid key file[/red]")

    with open(filepath, "rb") as f:
        message=f.read()

    ciphetext=rsa.encryptfile(message, key)
    output=input("Please enter a filename for the encrypted file (press enter to skip): ")
    if output==None or output=="":
        output=f'ciphertext_{datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")}'

    output+=".enc"

    #writes to a file    
    with open(output,"wb") as f:
        f.write(ciphetext)
    if os.path.exists(output):
        rprint(f"The encrypted file have been saved here => [magenta]{output}[/magenta]")
    else: rprint(f"[red]There was an error in saving the file[/red]")        

mythcrypt.add_command(encryptfile)



@click.command()
@click.option("--key", "-k", type=click.Path(), help='Path to a file or directory.', prompt="Enter path to encryption(private) key:")
@click.option("--filepath", "-f", help="The path to the file to be decrypted", prompt="Enter filepath of the file to decrypt")
@click.option("--output", "-o",help="output file bool", default=f'decyphered_{datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")}.txt')
def decryptfile(key, filepath, output ):
    #loading the key
    if os.path.exists(key):
        key=rsa.load_private(key)
    else: rprint(f"[red]Invalid key file[/red]")

    #if filepath is given overrides the message even if it was given
    with open(filepath, "rb") as f:
        message=f.read()

    ciphetext=rsa.decrypt(message, key)
    output=input("Please enter a filename for the decrypted file (press enter to skip): ")
    if output==None or output=="":
        output=f'decyphered_{datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")}'
    
    output+=".txt"

    #writes to a file
    with open(output,"wb") as f:
        f.write(ciphetext)
    if os.path.exists(output):
        rprint(f"The encrypted file have been saved here => [magenta]{output}[/magenta]")
    else: rprint(f"[red]There was an error in saving the file[/red]")
        
mythcrypt.add_command(decryptfile)





#running the main program
if __name__ == "__main__":
    # print(f"file running at => {os.path.dirname(__file__)}")
    mythcrypt()