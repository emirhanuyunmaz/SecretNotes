import tkinter
import tkinter.messagebox
import secrets
from PIL import ImageTk, Image
from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

backend = default_backend()
iterations = 100_000

fileText="SecretNotes.txt"
file=open(fileText,"a+" , encoding="utf-8")

#-----------------------Cryp------------------------
def _derive_key(password: bytes, salt: bytes, iterations: int = iterations) -> bytes:
    """Derive a secret key from a given password and salt"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt,
        iterations=iterations, backend=backend)
    return b64e(kdf.derive(password))

def encryptText(message: bytes, password: str, iterations: int = iterations) -> bytes:
    salt = secrets.token_bytes(16)
    key = _derive_key(password.encode(), salt, iterations)
    return b64e(
        b'%b%b%b' % (
            salt,
            iterations.to_bytes(4, 'big'),
            b64d(Fernet(key).encrypt(message)),
        )
    )

def decryptText(token: bytes, password: str) -> bytes:
    decoded = b64d(token)
    salt, iter, token = decoded[:16], decoded[16:20], b64e(decoded[20:])
    iterations = int.from_bytes(iter, 'big')
    key = _derive_key(password.encode(), salt, iterations)
    return Fernet(key).decrypt(token)


#----------------Func Save------------------
def saveButton_OnClick():
    if  text.compare("end-1c", "==", "1.0") or entryHeader.get()=="" or entryKey.get()=="":
        tkinter.messagebox.showerror(title='ERROR', message="Please enter a text.", )
    else:
        key=entryKey.get()
        textGet=text.get("1.0",tkinter.END)
        encryptT=encryptText(textGet.encode(), key).decode()
        print(encryptT)
        #file op.
        file.write(str(entryHeader.get())+"\n")
        file.write(encryptT+"\n\n")

#----------------Func Decode-----------------
def decodeButton_OnClick():
    key=entryKey.get()
    textGet = text.get("1.0", tkinter.END)
    decryptT=str(decryptText(textGet, key).decode())
    print(decryptT)
    text.delete(1.0, tkinter.END)
    text.insert("end-1c", decryptT)

#-----------------Window---------------------
window=tkinter.Tk()
window.title("Secret Notes")
window.minsize(width=450,height=500)

#-------------------Label--------------------
top_secret_Label=tkinter.Label(text="TOP SECRET")
top_secret_Label.pack()

#----------------Label-----------------------
labelTitle=tkinter.Label(text="Enter Your Title")
labelTitle.pack()

#------------------Entry Header-----------------------
entryHeader=tkinter.Entry(width=20)
entryHeader.pack()

#----------------Label------------------------
labelText=tkinter.Label(text="Enter Your Secret")
labelText.pack()

#----------------Text----------------------
text=tkinter.Text(width=30,height=15)
text.pack()

#---------------Label-----------------------
labelKey=tkinter.Label(text="Enter Master Key")
labelKey.pack()

#--------------Entry Master Key------------------------
entryKey=tkinter.Entry(width=20)
entryKey.pack()

#-------------Button Save-------------------------
buttonSave=tkinter.Button(text="Save" , command=saveButton_OnClick)
buttonSave.pack()

#------------Button Decode--------------------------
buttonDecode=tkinter.Button(text="Decode" , command=decodeButton_OnClick)
buttonDecode.pack()

window.mainloop()