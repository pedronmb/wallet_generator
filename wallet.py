#generar clave privada para la wallet de ethereum
from secp256k1 import PrivateKey, PublicKey
#from Crypto.Hash import keccak
#from eth_hash.auto import keccak
#from sha3 import keccak_256
from eth_account import Account
from tkinter import *
from tkinter import messagebox
from tkinter import simpledialog
import tkinter as tk
import random
from tkinter import ttk
from tkinter import scrolledtext

'''
key = "0000000000000000000000000000000000000000000000000000000000000001"
base_key = "0000000000000000000000000000000000000000000000000000000000000000"
#transformar clave privada a integer
key = int(key, 16)

#sumarle 1 a la clave privada
key = key + 1
#transformar clave privada a hexadecimal
key = hex(key)
#transformar clave privada a string
key = str(key)
#quitar los caracteres 0x de la clave privada
key = key[2:]
#contar la cantidad de caracteres de la clave privada
length = len(key)
#agregar los ceros faltantes a la clave privada
base_key = base_key[:64-length]
key = base_key + key


words = mnemo.generate(strength=128)
print(words)
'''

def on_button_click():
    key = entry1.get()
    if len(key) != 64:
        messagebox.showerror("Error", "La clave privada debe tener 64 caracteres")
        return
    text2 = entry2.get()
    #generar clave privada
    privkey = PrivateKey(bytes(bytearray.fromhex(key)))
    pubkey_ser = privkey.pubkey.serialize()
    pubkey_ser_uncompressed = privkey.pubkey.serialize(compressed=False)


    #mostrar en pantalla public key
    print(pubkey_ser_uncompressed.hex())
    entry2.delete(0, tk.END)
    entry2.insert(0, pubkey_ser_uncompressed.hex())

    #mostrar en pantalla private key
    print(privkey.private_key.hex())

    #generar cuenta
    key = "0x" + key
    acct = Account.from_key(key)
    print("Address:", acct.address)
    entry3.delete(0, tk.END)
    entry3.insert(0, acct.address)

def on_button_random_click():
    key = "0000000000000000000000000000000000000000000000000000000000000001"
    base_key = "0000000000000000000000000000000000000000000000000000000000000000"
    #transformar clave privada a integer
    key = int(key, 16)

    #sumarle 1 a la clave privada
    key = random.randint(1, 115792089237316195423570985008687907852837564279074904382605163141518161494337)
    #transformar clave privada a hexadecimal
    key = hex(key)
    #transformar clave privada a string
    key = str(key)
    #quitar los caracteres 0x de la clave privada
    key = key[2:]
    #contar la cantidad de caracteres de la clave privada
    length = len(key)
    #agregar los ceros faltantes a la clave privada
    base_key = base_key[:64-length]
    key = base_key + key


    entry1.delete(0, tk.END)
    entry1.insert(0, key)

# Crear la ventana
window = tk.Tk()
window.title("Ejemplo de ventana con campos de texto y botón")
window.geometry("1200x600")
# Crear los labels



label0 = tk.Label(window, text="")
label0.pack()
# Crear los campos de texto
entry1 = tk.Entry(window, width=70, justify="center")
entry1.pack()

label1 = tk.Label(window, text="Clave privada")
label1.pack()

buttonR = tk.Button(window, text="Random", command=on_button_random_click)
buttonR.pack()

entry2 = tk.Entry(window, width=130, justify="center")
entry2.pack()

label2 = tk.Label(window, text="clave publica")
label2.pack()

entry3 = tk.Entry(window, width=50, justify="center")
entry3.pack()

label3 = tk.Label(window, text="Address")
label3.pack()

# Crear el botón
button = tk.Button(window, text="Aceptar", command=on_button_click)
button.pack()

# Ejecutar el bucle principal
window.mainloop()

