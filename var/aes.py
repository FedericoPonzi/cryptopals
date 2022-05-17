import base64
from Crypto.Cipher import AES

key = [ 0x71, 0x19, 0x64, 0x4E, 0x34, 0x4B, 0x52, 0x34, 0xB4, 0x13, 0x8D, 0x80, 0xB8, 0x1F, 0x7C, 0xEA, ]
iv = [0x00]*16

plaintext = """The Advanced Encryption Standard (AES) 
also known by its original name Rijndael
is a specification for the encryption of electronic data established 
by the U.S. National Institute of Standards and Technology (NIST) in 2001"""



key = bytes(key)
iv = bytes(iv)
aes = AES.new(key, AES.MODE_CBC, iv)

print(base64.b64encode(aes.encrypt(plaintext)))
print("-----")

aes = AES.new(key, AES.MODE_CBC, iv)
encrypted_b64 = "HuYGLtQ4sKTjCWc7rQsTwZloiz6GMzxxZpjY2OZBrs++OZqsl1QMLKR2Hc9wPlZWSlO1ZAo7EQh3ZdqkKzbXrH4hODLcBxLXkQqPrMjw9Jtq/aQuxCAFT35A6Nn9V4dol0hOeXUFvK5IVWWAxZ0ccA=="
print(aes.decrypt(base64.b64decode(encrypted_b64)))

