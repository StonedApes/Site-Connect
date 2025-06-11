import secrets

# Generate a 32-character random string (16 bytes in hex = 32 characters)
secret_key = secrets.token_hex(16)
print(secret_key)