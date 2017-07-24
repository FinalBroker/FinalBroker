import hmac
import hashlib

from time import time as _time
from struct import pack

class TOTK(object):
    """
    TOTK - _time Based One _time Key Class
    digest: pre-shared key
    tolerance: tolerance (in milllion seconds) for _time mismatch
    digest: digest method (This will affect output key length)
    """
    def __init__(self, secret: bytes,
                       tolerance: int=200, 
                       digest: callable=hashlib.sha256):
        self.digest = digest
        self.secret = secret
        self.tolerance = tolerance/1000

    def get_key(self, time: int=None):
        if time is None:
            time = int(_time()//self.tolerance)
        _hmac = hmac.new(self.secret, pack('l',time), digestmod=self.digest)
        return _hmac.digest()

    def verify(self, key, time: int=None):
        if time is None:
            time = int(_time()//self.tolerance)
            return any(self.get_key(time + i) == key for i in range(-1, 2))
        return self.get_key(time) == key
        