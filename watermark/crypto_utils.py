from cryptography.fernet import Fernet

# Générer une clé de chiffrement
def generate_key():
    return Fernet.generate_key()

# Chiffrer un fichier
def encrypt_file(file_path, key):
    with open(file_path, "rb") as file:
        file_data = file.read()
        cipher = Fernet(key)
        encrypted_data = cipher.encrypt(file_data)
        return encrypted_data
