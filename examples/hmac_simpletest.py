import circuitpython_hmac as hmac

secret = "secret"
msg = "message"

key = hmac.new(secret, msg=msg).digest()
