from stegano import lsb
from cryptography.fernet import Fernet

# Extraire le message caché dans l'image
def extract_message_from_image(image_path):
    extracted_message = lsb.reveal(image_path)
    return extracted_message

# Déchiffrer le message extrait
def decrypt_message(cipher_text, key):
    cipher_suite = Fernet(key)
    decrypted_message = cipher_suite.decrypt(cipher_text.encode())
    return decrypted_message.decode()

# Exemple d'utilisation
def main():
    image_path = "watermarked_image.png"  # L'image avec le message caché
    key = b"votre_clef_ici"  # La même clé que pour le chiffrement (doit être conservée en sécurité)

    # Extraire le message de l'image
    extracted_message = extract_message_from_image(image_path)
    print("Message extrait:", extracted_message)

    # Déchiffrer le message
    decrypted_message = decrypt_message(extracted_message, key)
    print("Message déchiffré:", decrypted_message)

if __name__ == "__main__":
    main()
