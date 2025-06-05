# watermark/utils/stego_utils.py

from PIL import Image
from typing import List

def _int_to_bits(x: int, length: int) -> List[int]:
    """Convertit un entier en une liste de bits (MSB first)."""
    return [(x >> i) & 1 for i in reversed(range(length))]

def _bytes_to_bits(data: bytes) -> List[int]:
    """Convertit un buffer d’octets en une liste de bits."""
    bits: List[int] = []
    for byte in data:
        bits.extend(_int_to_bits(byte, 8))
    return bits

def embed_bytes_in_image(input_image_path: str, data: bytes, output_image_path: str):
    """
    Insère les octets `data` dans l’image `input_image_path` en LSB,
    en préfixant le flux par 4 octets de longueur. Sauvegarde en PNG.
    """
    img = Image.open(input_image_path)
    if img.mode not in ('RGB', 'RGBA'):
        img = img.convert('RGBA')
    pixels = img.load()

    # Préparer les octets à cacher : 4 octets de longueur + data
    length = len(data)
    header = length.to_bytes(4, byteorder='big')
    full_bytes = header + data
    bits = _bytes_to_bits(full_bytes)

    width, height = img.size
    max_capacity = width * height * 3
    if len(bits) > max_capacity:
        raise ValueError("Pas assez de capacité pour cacher ces données dans l’image.")

    idx = 0
    for y in range(height):
        for x in range(width):
            if idx >= len(bits):
                break
            pixel = list(pixels[x, y])
            # Modifier le LSB de chaque canal R, G, B tant qu’il reste des bits
            for channel in range(3):
                if idx < len(bits):
                    pixel[channel] = (pixel[channel] & 0xFE) | bits[idx]
                    idx += 1
            pixels[x, y] = tuple(pixel)
        if idx >= len(bits):
            break

    img.save(output_image_path, format='PNG')


def extract_bytes_from_image(stego_image_path: str) -> bytes:
    """
    Lit l’image `stego_image_path`, extrait d’abord 32 bits (4 octets) pour
    déterminer la longueur, puis récupère ce nombre d’octets suivants.
    Retourne le buffer complet (bytes).
    """
    img = Image.open(stego_image_path)
    if img.mode not in ('RGB', 'RGBA'):
        img = img.convert('RGBA')
    pixels = img.load()

    width, height = img.size

    # 1) Lire 32 bits pour récupérer la longueur en octets
    length_bits: List[int] = []
    idx = 0
    for y in range(height):
        for x in range(width):
            pixel = pixels[x, y]
            for channel in range(3):
                if idx < 32:
                    length_bits.append(pixel[channel] & 1)
                    idx += 1
                else:
                    break
            if idx >= 32:
                break
        if idx >= 32:
            break

    length = 0
    for bit in length_bits:
        length = (length << 1) | bit

    # 2) Lire length*8 bits suivants pour reconstituer les octets
    data_bits: List[int] = []
    needed = length * 8
    idx2 = 0
    total_idx = 0  # nombre total de bits lus (pour sauter les 32 premiers)
    for y in range(height):
        for x in range(width):
            pixel = pixels[x, y]
            for channel in range(3):
                if total_idx >= 32 and idx2 < needed:
                    data_bits.append(pixel[channel] & 1)
                    idx2 += 1
                total_idx += 1
                if idx2 >= needed:
                    break
            if idx2 >= needed:
                break
        if idx2 >= needed:
            break

    data_bytes = bytearray()
    for i in range(0, len(data_bits), 8):
        byte = 0
        for b in data_bits[i : i + 8]:
            byte = (byte << 1) | b
        data_bytes.append(byte)

    return bytes(data_bytes)
