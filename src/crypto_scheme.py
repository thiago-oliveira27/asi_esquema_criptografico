"""
Módulo de Esquema Criptográfico Simplificado

Este módulo implementa um esquema criptográfico educacional com três funções principais:
- GEN: Geração determinística de chave a partir de uma seed
- ENC: Criptografia de mensagem usando chave
- DEC: Descriptografia de cifra usando chave

AVISO: Este é um esquema educacional. NÃO use em produção.
"""

import hashlib
import random
from typing import List


class CryptoScheme:
    """
    Classe auxiliar que implementa operações criptográficas de baixo nível.
    
    Características:
    - S-Box e P-Box para transformações não-lineares
    - Derivação de subchaves
    - Operações de blocos
    """
    
    def __init__(self):
        """Inicializa o esquema criptográfico."""
        self.BLOCK_SIZE = None  # Tamanho do bloco em bits
        self.NUM_ROUNDS = 12  # Número de rodadas de transformação
        self.pboxes = None
        
    # ==================== Funções Auxiliares ====================
    
    def _bits_to_bytes(self, bits: List[int]) -> bytes:
        """
        Converte lista de bits em bytes.
        
        Args:
            bits: Lista de bits (0 ou 1)
            
        Returns:
            Bytes correspondentes
        """
        # Adicionar padding se necessário
        padded_bits = bits + [0] * ((8 - len(bits) % 8) % 8)
        
        byte_array = []
        for i in range(0, len(padded_bits), 8):
            byte_value = 0
            for j in range(8):
                byte_value = (byte_value << 1) | padded_bits[i + j]
            byte_array.append(byte_value)
        
        return bytes(byte_array)
    
    def _validate_binary_list(self, bits: List[int], name: str):
        """Valida que uma lista contém apenas 0's e 1's."""
        if not bits or len(bits) == 0:
            raise ValueError(f"{name} não pode ser vazia")
        if not all(bit in [0, 1] for bit in bits):
            raise ValueError(f"{name} deve conter apenas 0's e 1's")
    
    def _split_into_blocks(self, bits: List[int], block_size: int) -> List[List[int]]:
        """
        Divide lista de bits em blocos de tamanho fixo.
        
        Args:
            bits: Lista de bits
            block_size: Tamanho de cada bloco
            
        Returns:
            Lista de blocos
        """
        blocks = []
        for i in range(0, len(bits), block_size):
            block = bits[i:i + block_size]
            # Adicionar padding se necessário
            if len(block) < block_size:
                block = block + [0] * (block_size - len(block))
            blocks.append(block)
        return blocks
    
    def _derive_subkeys(self, key: List[int], num_rounds: int) -> List[List[int]]:
        """
        Deriva subchaves a partir da chave principal.
        
        Args:
            key: Chave principal
            num_rounds: Número de subchaves a gerar
            
        Returns:
            Lista de subchaves
        """
        subkeys = []
        key_bytes = self._bits_to_bytes(key)
        
        for round_num in range(num_rounds):
            # Usar SHA-256 com contador para gerar cada subchave
            h = hashlib.sha256(key_bytes + round_num.to_bytes(4, 'big'))
            digest = h.digest()
            
            # Extrair bits da subchave (mesmo tamanho da chave original)
            subkey = []
            for byte in digest:
                for i in range(8):
                    if len(subkey) < len(key):
                        subkey.append((byte >> (7 - i)) & 1)
            
            subkeys.append(subkey[:len(key)])
        
        return subkeys
    
    def _encrypt_block(self, block: List[int], subkeys: List[List[int]]) -> List[int]:
        """
        Criptografa um bloco usando múltiplas rodadas.
        
        Args:
            block: Bloco de bits a criptografar
            subkeys: Lista de subchaves
            
        Returns:
            Bloco criptografado
        """
        current_block = block[:]
        
        for round_num in range(self.NUM_ROUNDS):
            # XOR com subchave
            subkey_block = subkeys[round_num][:len(block)]
            current_block = self._xor(current_block, subkey_block)
            
            # S-Box (substituição)
            current_block = self._apply_sbox(current_block)
            
            # P-Box (permutação)
            current_block = self._apply_pbox(current_block, round_num)
        
        return current_block
    
    def _decrypt_block(self, block: List[int], subkeys: List[List[int]]) -> List[int]:
        """
        Descriptografa um bloco (reversão das operações de criptografia).
        
        Args:
            block: Bloco de bits a descriptografar
            subkeys: Lista de subchaves (mesmas da criptografia)
            
        Returns:
            Bloco descriptografado
        """
        current_block = block[:]
        
        # Aplicar transformações na ordem reversa
        for round_num in range(self.NUM_ROUNDS - 1, -1, -1):
            # P-Box inversa
            current_block = self._apply_pbox_inverse(current_block, round_num)
            
            # S-Box inversa
            current_block = self._apply_sbox_inverse(current_block)
            
            # XOR com subchave (XOR é auto-inverso)
            subkey_block = subkeys[round_num][:len(block)]
            current_block = self._xor(current_block, subkey_block)
        
        return current_block
    
    def _xor(self, bits1: List[int], bits2: List[int]) -> List[int]:
        """Operação XOR bit a bit."""
        min_len = min(len(bits1), len(bits2))
        return [bits1[i] ^ bits2[i] for i in range(min_len)]
    
    def _apply_sbox(self, block: List[int]) -> List[int]:
        """
        Aplica S-Box (substituição não-linear) ao bloco usando tabela de lookup.
        
        S-Box de 4 bits (16 entradas) garantidamente invertível.
        """
        # S-Box projetada para alta não-linearidade
        sbox_table = [
            0xE, 0x4, 0xD, 0x1, 0x2, 0xF, 0xB, 0x8,
            0x3, 0xA, 0x6, 0xC, 0x5, 0x9, 0x0, 0x7
        ]
        
        result = []
        for i in range(0, len(block), 4):
            # Pegar 4 bits por vez
            nibble = block[i:i+4]
            if len(nibble) < 4:
                nibble = nibble + [0] * (4 - len(nibble))
            
            # Converter para inteiro
            value = (nibble[0] << 3) | (nibble[1] << 2) | (nibble[2] << 1) | nibble[3]
            
            # Aplicar S-Box
            output_value = sbox_table[value]
            
            # Converter de volta para bits
            output_bits = [
                (output_value >> 3) & 1,
                (output_value >> 2) & 1,
                (output_value >> 1) & 1,
                output_value & 1
            ]
            
            result.extend(output_bits)
        
        return result[:len(block)]
    
    def _apply_sbox_inverse(self, block: List[int]) -> List[int]:
        """
        Aplica S-Box inversa ao bloco.
        
        Usa tabela de lookup inversa pré-computada.
        """
        # S-Box inversa (inversão da tabela acima)
        sbox_inv_table = [
            0xE, 0x3, 0x4, 0x8, 0x1, 0xC, 0xA, 0xF,
            0x7, 0xD, 0x9, 0x6, 0xB, 0x2, 0x0, 0x5
        ]
        
        result = []
        for i in range(0, len(block), 4):
            # Pegar 4 bits por vez
            nibble = block[i:i+4]
            if len(nibble) < 4:
                nibble = nibble + [0] * (4 - len(nibble))
            
            # Converter para inteiro
            value = (nibble[0] << 3) | (nibble[1] << 2) | (nibble[2] << 1) | nibble[3]
            
            # Aplicar S-Box inversa
            output_value = sbox_inv_table[value]
            
            # Converter de volta para bits
            output_bits = [
                (output_value >> 3) & 1,
                (output_value >> 2) & 1,
                (output_value >> 1) & 1,
                output_value & 1
            ]
            
            result.extend(output_bits)
        
        return result[:len(block)]

    def _generate_pboxes(self):
        """Gera as P-Boxes para todas as rodadas."""
        self.pboxes = []
        for r in range(self.NUM_ROUNDS):
            p = list(range(self.BLOCK_SIZE))
            random.Random(r).shuffle(p)
            self.pboxes.append(p)

    def _apply_pbox(self, block: List[int], round_num: int) -> List[int]:
        """
        Aplica P-Box (permutação) ao bloco.
        
        Args:
            block: Bloco de bits
            round_num: Número da rodada
            
        Returns:
            Bloco permutado
        """
        pbox = self.pboxes[round_num]
        return [block[i] for i in pbox]
    
    def _apply_pbox_inverse(self, block: List[int], round_num: int) -> List[int]:
        """
        Aplica P-Box inversa ao bloco.
        
        Reverte a permutação aplicada por _apply_pbox.
        """
        pbox = self.pboxes[round_num]
        inv = [0] * len(pbox)
        for i, p in enumerate(pbox):
            inv[p] = i
        return [block[i] for i in inv]


# ==================== Funções Públicas ====================

def GEN(seed: List[int]) -> List[int]:
    """
    Gera chave binária a partir de uma semente usando expansão SHA-256.
    
    Args:
        seed: Lista de inteiros (0 ou 1) representando a semente
        
    Returns:
        Lista de inteiros (0 ou 1) com tamanho 4 * len(seed)
        
    Raises:
        ValueError: Se seed não for válida (não binária ou vazia)
        
    Example:
        >>> seed = [1, 0, 1, 1, 0, 1, 0, 1]
        >>> key = GEN(seed)
        >>> len(key) == 4 * len(seed)
        True
    """
    # Validação de entrada
    if not seed or len(seed) == 0:
        raise ValueError("Seed não pode ser vazia")
    if not all(bit in [0, 1] for bit in seed):
        raise ValueError("Seed deve conter apenas 0's e 1's")
    
    # Criar instância auxiliar para conversão
    crypto = CryptoScheme()
    
    # Converter seed para bytes
    seed_bytes = crypto._bits_to_bytes(seed)
    
    # Expandir usando SHA-256
    key_bits = []
    target_len = 4 * len(seed)
    counter = 0
    
    while len(key_bits) < target_len:
        # Concatenar seed com contador para gerar blocos diferentes
        h = hashlib.sha256(seed_bytes + counter.to_bytes(4, 'big'))
        digest = h.digest()
        
        # Extrair bits do digest
        for byte in digest:
            for i in range(8):
                if len(key_bits) < target_len:
                    key_bits.append((byte >> (7 - i)) & 1)
                else:
                    break
            if len(key_bits) >= target_len:
                break
        
        counter += 1
    
    return key_bits[:target_len]


def ENC(K: List[int], M: List[int]) -> List[int]:
    """
    Criptografa mensagem usando chave com múltiplas camadas de transformação.
    
    Args:
        K: Chave binária (tamanho 4 * len(seed))
        M: Mensagem binária (tamanho 4 * len(seed))
        
    Returns:
        Cifra binária (mesmo tamanho de M)
        
    Raises:
        ValueError: Se entradas não forem válidas ou tamanhos incompatíveis
    """
    # Criar instância do esquema criptográfico
    crypto = CryptoScheme()
    
    # Validação de entrada
    crypto._validate_binary_list(K, "Chave")
    crypto._validate_binary_list(M, "Mensagem")
    
    if len(K) != len(M):
        raise ValueError(f"Chave e mensagem devem ter mesmo tamanho. K={len(K)}, M={len(M)}")
    
    # Configurar tamanho do bloco e gerar P-Boxes
    crypto.BLOCK_SIZE = len(M)
    crypto._generate_pboxes()
    
    # Derivar subchaves
    subkeys = crypto._derive_subkeys(K, crypto.NUM_ROUNDS)
    
    # Dividir mensagem em blocos
    blocks = crypto._split_into_blocks(M, crypto.BLOCK_SIZE)
    encrypted_blocks = []
    
    # Processar cada bloco
    for block in blocks:
        encrypted_block = crypto._encrypt_block(block, subkeys)
        encrypted_blocks.extend(encrypted_block)
    
    return encrypted_blocks


def DEC(K: List[int], C: List[int]) -> List[int]:
    """
    Descriptografa cifra usando chave (operação reversa de ENC).
    
    Args:
        K: Chave binária (tamanho 4 * len(seed))
        C: Cifra binária (tamanho 4 * len(seed))
        
    Returns:
        Mensagem original binária
        
    Raises:
        ValueError: Se entradas não forem válidas ou tamanhos incompatíveis
    """
    # Criar instância do esquema criptográfico
    crypto = CryptoScheme()
    
    # Validação de entrada
    crypto._validate_binary_list(K, "Chave")
    crypto._validate_binary_list(C, "Cifra")
    
    if len(K) != len(C):
        raise ValueError(f"Chave e cifra devem ter mesmo tamanho. K={len(K)}, C={len(C)}")
    
    # Configurar tamanho do bloco e gerar P-Boxes (mesmo da encriptação)
    crypto.BLOCK_SIZE = len(C)
    crypto._generate_pboxes()
    
    # Derivar subchaves (mesmas da criptografia)
    subkeys = crypto._derive_subkeys(K, crypto.NUM_ROUNDS)
    
    # Dividir cifra em blocos
    blocks = crypto._split_into_blocks(C, crypto.BLOCK_SIZE)
    decrypted_blocks = []
    
    # Processar cada bloco (ordem reversa das transformações)
    for block in blocks:
        decrypted_block = crypto._decrypt_block(block, subkeys)
        decrypted_blocks.extend(decrypted_block)
    
    return decrypted_blocks


# Exemplo de uso
if __name__ == "__main__":
    # Teste básico
    seed = [1, 0, 1, 1, 0, 1, 0, 1]
    print(f"Seed: {seed}")
    
    key = GEN(seed)
    print(f"Key length: {len(key)} (expected: {4 * len(seed)})")
    
    message = [1, 0] * (len(key) // 2)
    print(f"Message length: {len(message)}")
    
    cipher = ENC(key, message)
    print(f"Cipher length: {len(cipher)}")
    
    decrypted = DEC(key, cipher)
    print(f"Decrypted length: {len(decrypted)}")
    
    print(f"Decryption correct: {message == decrypted}")