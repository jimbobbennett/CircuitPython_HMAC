import adafruit_hmac as hmac
import adafruit_hashlib as hashlib

secret = "secret"
msg = "message"

key = hmac.new(secret, msg=msg, digestmod=hashlib.sha256).digest()
