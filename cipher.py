import os

from Crypto.Cipher import AES

class AESCipher():
    """
    AESCipher
    A wrapper for AES encrypt/decrypt.
    Using PKCS5 padding.
    """
    def __init__(self, key: bytes,
                       iv: bytes=None,
                       is_encrypt: bool=True,
                       mode=AES.MODE_CBC):
        self.key = key
        if iv:
            self.iv = iv
        else:
            self.iv = os.urandom(16)
        self.cipher = AES.new(key, AES.MODE_CBC, self.iv)
        if is_encrypt:
            self.update = self.__encrypt
        else:
            self.update = self.__decrypt

    def __pad(self, data: bytes) -> bytes:
        BS = AES.block_size
        length = len(data)
        padding = (BS - length % BS) * chr(BS - length % BS).encode()
        return data + padding
    
    def __unpad(self, data: bytes) -> bytes:
        return data[0:-data[-1]]

    def __encrypt(self, data: bytes) -> bytes:
        return self.cipher.encrypt(self.__pad(data))

    def __decrypt(self, data: bytes) -> bytes:
        return self.__unpad(self.cipher.decrypt(data))

    