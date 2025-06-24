# imports

# imports for shell
import sys
import datetime
import os
from pathlib import Path
import json
import click
from click_shell import shell
from rich import print as rprint
from rich.console import Console
from rich.table import Table

import rsa





# vars and innit

## global
v="v 0.1.0" #version
loadedkeys={'public':None, 
            'private':None}

console= Console()

## Check if the mythcrypt_data directory exists, if not create it
mythcrypt_data=os.path.join(os.getenv("LOCALAPPDATA"), 'mythcrypt')
if not os.path.exists(mythcrypt_data):
    try:
        # Subdirectories to create
        subdirs = ["ciphers", "keys", "messages"]

        # Create main and subdirectories
        for sub in subdirs:
            path = os.path.join(mythcrypt_data, sub)
            os.makedirs(path, exist_ok=True)
    except Exception as e:
        rprint(f"[red]Error creating mythcrypt data directory: {e}[/red]")



# shell start function
@shell(prompt="mythcrypt >", intro=f"""Welcome to the Mythcrypt console [{v}].
Your command-line companion for mythically secure file encryption.
Type "exit" or "help" for more information. 
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

Default data directory: [magenta][link={mythcrypt_data}]{mythcrypt_data}[/link][/magenta]

Use the commands below to interact with MythCrypt. Type a command and press [bold]Enter[/bold] to execute it.
""")

    table=Table(title="Available Commands", header_style="bold magenta", border_style="dim")
    table.add_column("Command", style="cyan", no_wrap=True)
    table.add_column("Description", style="white")

    table.add_row("help", "Show this help menu")
    table.add_row("version", "Display the current version of MythCrypt")
    table.add_row("generatekeys", "Generate a new RSA public-private key pair")
    table.add_row("generatepublic", "Generate a public key from a private key")
    table.add_row("encryptfile", "Encrypt a file using a public key")
    table.add_row("decryptfile", "Decrypt a file using a private key") 
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
[bold green][link=https://github.com/swasal/Mythcrypt]https://github.com/swasal/Mythcrypt[/link][/bold green]
""")   



@click.command()
def version():
    rprint(f"Current Mythcrypt version is =>[bold magenta]{v}[/bold magenta]")

mythcrypt.add_command(version)



@click.command()
@click.option("--path", "-p", type=click.Path(), help='Path to a file or directory.')
def generatekeys(path):
    #take the inputs
    path=input("Enter path to save key pair (or press Enter to use default) => ")

    if path==None or path=="":
        path=os.path.join(mythcrypt_data, "Keys")
    else:
        rprint(f"Path found\n")
    with console.status("Generating keys...\n", spinner="dots"):
        path=rsa.newkeys(path)
        rprint(f"[green]The keys have been generated succesfully[/green]\nThe keypair have been saved here => [#ffcb03][link={path}]{path}[/link]\n")
mythcrypt.add_command(generatekeys)



@click.command()
@click.option("--pathprivate", "-p", type=click.Path(), help='Path to the private key file.')
@click.option("--pathpublic", "-p", type=click.Path(), help='Path to the public key file.')
def loadkeys(pathprivate, pathpublic):
    global loadedkeys
    #take the inputs
    pathprivate=input("Enter path to private key (press enter to leave blank) => ")
    pathpublic=input("Enter path to public key (press enter to leave blank) => ")

    with console.status("Loading keys keys...\n", spinner="dots"):
        if pathprivate!=None or pathprivate!="" :
            loadedkeys["private"]=pathprivate
            rprint(f"[green]Successfully loaded private key[/green]")
        else:
            rprint(f"[yellow]No private key to load[/yellow]")
        if pathpublic!=None or pathpublic!="":
            loadedkeys["public"]=pathpublic
            rprint(f"[green]Successfully loaded public key[/green]")
        else:
            rprint(f"[yellow]No public key to load[/yellow]")
        
mythcrypt.add_command(loadkeys)



@click.command()
@click.option("--path", "-p", type=click.Path(), help='Path to a private key.', )
def generatepublic(path):
    if loadedkeys["private"] is not None:
        path=loadedkeys["private"]
        rprint(f"[green]Loaded key found[/green]\n")
        rprint(f"[yellow]Do you want to use the loaded key?[/yellow]\n")
        if input("(y/n) => ").lower() != 'y':
            path=input("Enter path to private key => ")
            if path=="None":
                rprint(f"[red]No path provided[/red]\n")
                sys.exit(1)
            else:
                rprint(f"Private key found\n")


    else:
        path=input("Enter path to private key => ")
        if path=="None":
            rprint(f"[red]No path provided[/red]\n")
            sys.exit(1)
        else:
            rprint(f"Private key found\n")

    name=input("Enter a name for the public key =")

    with console.status("Generating public key...\n", spinner="dots"):
        path=rsa.get_public_key(path, name)
        
    rprint(f"[green]The keys have been generated succesfully[/green]\nThe keypair have been saved here => [#ffcb03][link={path}]{path}[/link]\n")
    rprint(f"[#ffcb03][link={os.path.dirname(path)}]Link to folder[/link]")
mythcrypt.add_command(generatepublic)



@click.command()
@click.option("--key", "-k", type=click.Path(), help='Path to the private key.')
@click.option("--message", "-m",help="The message to be encrypted using th4e provided key")
def encryptmsg(key, message):
    # checks if there is a loaded key
    if loadedkeys["public"] is None:
        key=input("Enter path to encryption(public) key => ")
    else:
        key=loadedkeys["public"]

    #loading the key
    if os.path.exists(key):
        key=rsa.load_public(key)
    else: rprint(f"[red]Invalid key file[/red]")

    message=input("Enter message to be encrypted => ")
    ciphetext=rsa.encrypt(message, key)
    
    filename=f'ciphertext_{datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")}.enc'
    output=os.path.join(mythcrypt_data, "messages", filename)

    #writes to a file
    with open(output,"wb") as f:
        f.write(ciphetext)
    if os.path.exists(output):
        rprint(f"The encrypted file have been saved here => [#ffcb03][link={output}]{output}[/link]")
        rprint(f"[#ffcb03][link={os.path.join(mythcrypt_data, "messages")}]Link to folder[/link]")
    else: rprint(f"[red]There was an error in saving the file[/red]")
        
mythcrypt.add_command(encryptmsg)



@click.command()
@click.option("--key", "-k", type=click.Path(), help='Path to a file or directory.')
@click.option("--filepath", "-f", help="The path to the file to be encrypted")
def encryptfile(key, filepath):
    # checks if there is a loaded key
    if loadedkeys["public"] is None:
        key=input("Enter path to encryption(public) key => ")
    else:
        key=loadedkeys["public"]

    # checks if the filepath is given
    if filepath is None or filepath=="":
        filepath=input("Enter filepath of the file to encrypt => ")
        if not os.path.exists(filepath):
            rprint(f"[red]Invalid file path provided[/red]")
            sys.exit(1)
    
    #loading the key
    if os.path.exists(key):
        key=rsa.load_public(key)
    else: 
        rprint(f"[red]Invalid key file[/red]")
        sys.exit(1)


    ciphetext=rsa.encryptfile(filepath, key)

    filename=input("Please enter a filename for the encrypted file (press enter to skip): ")
    if filename==None or filename=="":
        filename=f'ciphertext_{datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")}'

    filename+=".tome"

    path= os.path.dirname(filepath)
    output=os.path.join(path, filename)

    #writes to a file    
    with open(output,"w") as f:
        json.dump(ciphetext, f, indent=4)
    if os.path.exists(output):
        rprint(f"The encrypted file have been saved here => [#ffcb03][link={output}]{output}[/link]")
        rprint(f"[#ffcb03][link={path}]Link to folder[/link]")
    else: rprint(f"[red]There was an error in saving the file[/red]")        

mythcrypt.add_command(encryptfile)



@click.command()
@click.option("--key", "-k", type=click.Path(), help='Path to a file or directory.')
@click.option("--filepath", "-f", help="The path to the file to be decrypted")
def decryptfile(key, filepath ):
    # checks if there is a loaded key
    if loadedkeys["private"] is None:
        key=input("Enter path to decryption(private) key => ")
    else:
        key=loadedkeys["private"]

    if filepath is None or filepath=="":
        filepath=input("Enter filepath of the file to decrypt => ")
        if not os.path.exists(filepath):
            rprint(f"[red]Invalid file path provided[/red]")
            sys.exit(1)

    #loading the key
    if os.path.exists(key):
        key=rsa.load_private(key)
    else: rprint(f"[red]Invalid key file[/red]")

    #if filepath is given overrides the message even if it was given
    with open(filepath, "r") as f:
        cipher=json.load(f)
    
    ciphetext, file_ext =rsa.decryptfile(cipher, key)
    
    filename=input("Please enter a filename for the decrypted file (press enter to skip): ")
    if filename==None or filename=="":
        filename=f'decyphered_{datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")}'
    
    filename+="."+file_ext

    path= os.path.dirname(filepath)
    output=os.path.join(path, filename)
    #writes to a file
    with open(output,"wb") as f:
        f.write(ciphetext)
    if os.path.exists(output):
        rprint(f"The encrypted file was succesfully saved here => [#ffcb03][link={output}]{output}[/link]")
        rprint(f"[#ffcb03][link={path}]Link to folder[/link]")
    else: rprint(f"[red]There was an error in saving the file[/red]")
        
mythcrypt.add_command(decryptfile)





#running the main program
if __name__=="__main__":
    # print(f"file running at => {os.path.dirname(__file__)}")
    mythcrypt()