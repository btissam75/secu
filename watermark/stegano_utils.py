# watermark/stegano_utils.py  
from PIL import Image  

def hide_message_in_image(image_path, message):  
    img = Image.open(image_path)  
    # Implémentation LSB (simplifiée)  
    binary_msg = ''.join(format(ord(c), '08b') for c in message)  
    # ... (voir exemple complet plus haut)  