# imports

# imports for shell
import time
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
Type "exit", "help", or "about" for more information.
""")
def mythcrypt():
    pass


#shell commands
@mythcrypt.command()
def help():
    # rprint("Visit my [link=https://www.google.com]blog[/link]!")
    rprint(f"""Welcome to Mythcrypt help. For a full documentation of Mythcrypt please refer to the 
Git-hub documentation => [link={"google.com"} style="green"]Mythcrypt[/link]!

Current version of Mythcrypt => [red]{v}[/red]

The commands available are shown below:""")

    table = Table(title=None, border_style="dim")

    table.add_column("[bold magenta]Commands[/bold magenta]", justify="left", style="magenta")
    table.add_column("[bold white]Description[/bold white]", justify="left", style="white")

    # table.add_row("command", "description")
    table.add_row("version", "shows the app version")
    table.add_row("help", "see this command")
    table.add_row("hello", "sends a `hello [name]` message")
    table.add_row("generatekeys","Generates a new rsa keypair")
    table.add_row("encrypt","Encrypt a file or message with the given key")
    table.add_row("decrypt","Decrypt a file or message with the given key")
    table.add_row("exit", "exits the console")
    console.print(table)



@click.command()
def version():
    global v
    rprint(f"Current Mythcrypt version is =>[bold magenta]{v}[/bold magenta]")

mythcrypt.add_command(version)



@click.command()
@click.option("--name", "-n",help="Name of user")
# @click.argument("name",type=str)
def hello(name):
    # name=input("Enter name: ")
    print(f"Hello {name}!")

mythcrypt.add_command(hello)




@click.command()
@click.option("--path", "-p", type=click.Path(), help='Path to a file or directory.', prompt="Enter path to save key pair")
def generatekeys(path):
    print(path)
    if path=="None":
        path=None
        
    else:
        rprint(f"Path found\nSaving keys here => [magenta]{path}[/magenta]\n")
    with console.status("Processing...\n", spinner="dots"):
        time.sleep(2)
        path=rsa.newkeys(path)
        rprint(f"[green]The keys have been generated succesfully[/green]\nThe files have been saved here => [magenta]{path}[/magenta]\n")

mythcrypt.add_command(generatekeys)



@click.command()
@click.option("--key", "-k", type=click.Path(), help='Path to a file or directory.', prompt="Enter path to encryption(public) key:")
@click.option("--message", "-m",help="The message to be encrypted using th4e provided key")
@click.option("--filepath", "-f", help="The path to the file to be encrypted")
@click.option("--output", "-o",help="output file bool", default=f'ciphertext_{datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")}.enc')
def encrypt(key, message, output, filepath):
    #loading the key
    if os.path.exists(key):
        key=rsa.load_public(key)
    else: rprint(f"[red]Invalid key file[/red]")

    #if filepath is given overrides the message even if it was given
    if filepath:
        with open(filepath, "rb") as f:
            message=f.read()

        ciphetext=rsa.encryptfile(message, key)
        output+=os.path.splitext(filepath)[-1]

    else:
        message=input("Enter message to be encrypted :")
        ciphetext=rsa.encrypt(message, key)


    #writes to a file

    with open(output,"wb") as f:
        f.write(ciphetext)
    if os.path.exists(output):
        rprint(f"The encrypted file have been saved here => [magenta]{output}[/magenta]")
    else: rprint(f"[red]There was an error in saving the file[/red]")
        

mythcrypt.add_command(encrypt)


@click.command()
@click.option("--path", "-p", type=click.Path(), help='Path to a file or directory.', prompt="Enter path to decryption(private) key:")
@click.option("--ciphertext", prompt="Enter ciphertext to decrypt", help="The message to be decrypted using the provided key")
def decrypt(path, ciphertext):
    if os.path.exists(path):
        ciphertext = eval(f"b'{ciphertext}'")
        key=rsa.load_private(path)
        print('loaded key')
        ciphetext=rsa.decrypt(ciphertext, key)
        rprint(f"The message is =>\n [magenta]{ciphetext}[/magenta]")

mythcrypt.add_command(decrypt)



@click.command()
@click.option('--path', type=click.Path(), help='Path to a file or directory.', prompt="Enter path")
def showpath(path):
    """Show the normalized path."""
    click.echo(f"Original path: {(path)}")

mythcrypt.add_command(showpath)

@click.command()
def devdata():
    """Show the developer info"""
    click.echo(f"The product is still in development stay tuned for more info.")

mythcrypt.add_command(devdata)


#running the main program
if __name__ == "__main__":
    # print(f"file running at => {os.path.dirname(__file__)}")
    mythcrypt()
    