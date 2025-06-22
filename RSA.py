#!/usr/bin/env python3
"""
Sistema de Geração e Verificação de Assinaturas RSA
Implementa geração de chaves, OAEP, assinatura e verificação usando SHA-3
"""

import hashlib
import os
import random
import base64
import json
from typing import Tuple, Optional

class RSASignatureSystem:
    def __init__(self):
        self.key_size = 1024  # bits
        
    def miller_rabin(self, n: int, k: int = 40) -> bool:
        """
        Teste de primalidade Miller-Rabin
        Args:
            n: número a ser testado
            k: número de rounds (maior = mais preciso)
        Returns:
            True se provavelmente primo, False se composto
        """
        if n < 2:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False
            
        # Escrever n-1 como d * 2^r
        r = 0
        d = n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
            
        # Teste Miller-Rabin
        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, d, n)
            
            if x == 1 or x == n - 1:
                continue
                
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
                
        return True
    
    def generate_prime(self, bits: int) -> int:
        """
        Gera um número primo com o número especificado de bits
        """
        while True:
            # Gera número ímpar aleatório com bits especificados
            candidate = random.getrandbits(bits)
            candidate |= (1 << bits - 1) | 1  # Garante que tem bits bits e é ímpar
            
            if self.miller_rabin(candidate):
                return candidate
    
    def extended_gcd(self, a: int, b: int) -> Tuple[int, int, int]:
        """
        Algoritmo euclidiano estendido
        Returns: (gcd, x, y) onde ax + by = gcd(a, b)
        """
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = self.extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y
    
    def mod_inverse(self, a: int, m: int) -> int:
        """
        Calcula o inverso modular de a mod m
        """
        gcd, x, _ = self.extended_gcd(a, m)
        if gcd != 1:
            raise ValueError("Inverso modular não existe")
        return (x % m + m) % m
    
    def generate_keypair(self) -> Tuple[dict, dict]:
        """
        Gera par de chaves RSA (pública e privada)
        Returns: (public_key, private_key)
        """
        print("Gerando chaves RSA...")
        
        # Gera dois primos grandes
        p = self.generate_prime(self.key_size // 2)
        q = self.generate_prime(self.key_size // 2)
        
        # Calcula n e φ(n)
        n = p * q
        phi_n = (p - 1) * (q - 1)
        
        # Escolhe e (geralmente 65537)
        e = 65537
        
        # Calcula d (inverso de e mod φ(n))
        d = self.mod_inverse(e, phi_n)
        
        public_key = {'n': n, 'e': e}
        private_key = {'n': n, 'd': d, 'p': p, 'q': q}
        
        print(f"Chaves geradas com sucesso!")
        print(f"Tamanho da chave: {n.bit_length()} bits")
        
        return public_key, private_key
    
    def mgf1(self, seed: bytes, length: int) -> bytes:
        """
        Mask Generation Function 1 (MGF1) baseada em SHA-256
        """
        if length >= (1 << 32) * 32:
            raise ValueError("mask too long")
            
        T = b""
        counter = 0
        while len(T) < length:
            C = counter.to_bytes(4, 'big')
            T += hashlib.sha256(seed + C).digest()
            counter += 1
            
        return T[:length]
    
    def oaep_encode(self, message: bytes, n: int, label: bytes = b"") -> bytes:
        """
        OAEP encoding (Optimal Asymmetric Encryption Padding)
        """
        k = (n.bit_length() + 7) // 8  # Tamanho em bytes
        m_len = len(message)
        
        # Verifica se a mensagem não é muito longa
        if m_len > k - 2 * 32 - 2:  # 32 = SHA-256 hash length
            raise ValueError("message too long")
            
        # Calcula hash da label
        l_hash = hashlib.sha256(label).digest()
        
        # Padding
        ps_len = k - m_len - 2 * 32 - 2
        ps = b'\x00' * ps_len
        
        # DB = lHash || PS || 0x01 || M
        db = l_hash + ps + b'\x01' + message
        
        # Gera seed aleatória
        seed = os.urandom(32)
        
        # dbMask = MGF(seed, k - hLen - 1)
        db_mask = self.mgf1(seed, k - 32 - 1)
        
        # maskedDB = DB ⊕ dbMask
        masked_db = bytes(a ^ b for a, b in zip(db, db_mask))
        
        # seedMask = MGF(maskedDB, hLen)
        seed_mask = self.mgf1(masked_db, 32)
        
        # maskedSeed = seed ⊕ seedMask
        masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))
        
        # EM = 0x00 || maskedSeed || maskedDB
        em = b'\x00' + masked_seed + masked_db
        
        return em
    
    def oaep_decode(self, encoded_message: bytes, n: int, label: bytes = b"") -> bytes:
        """
        OAEP decoding
        """
        k = (n.bit_length() + 7) // 8
        
        if len(encoded_message) != k or k < 2 * 32 + 2:
            raise ValueError("decryption error")
            
        # Separa componentes
        y = encoded_message[0]
        masked_seed = encoded_message[1:33]
        masked_db = encoded_message[33:]
        
        if y != 0:
            raise ValueError("decryption error")
            
        # Recupera seed
        seed_mask = self.mgf1(masked_db, 32)
        seed = bytes(a ^ b for a, b in zip(masked_seed, seed_mask))
        
        # Recupera DB
        db_mask = self.mgf1(seed, k - 32 - 1)
        db = bytes(a ^ b for a, b in zip(masked_db, db_mask))
        
        # Verifica lHash
        l_hash = hashlib.sha256(label).digest()
        l_hash_prime = db[:32]
        
        if l_hash != l_hash_prime:
            raise ValueError("decryption error")
            
        # Encontra separador 0x01
        i = 32
        while i < len(db) and db[i] == 0:
            i += 1
            
        if i >= len(db) or db[i] != 1:
            raise ValueError("decryption error")
            
        return db[i + 1:]
    
    def rsa_encrypt(self, message: bytes, public_key: dict) -> bytes:
        """
        Cifração RSA com OAEP
        """
        # OAEP encoding
        encoded = self.oaep_encode(message, public_key['n'])
        
        # Converte para inteiro
        m = int.from_bytes(encoded, 'big')
        
        # Cifração RSA: c = m^e mod n
        c = pow(m, public_key['e'], public_key['n'])
        
        # Converte para bytes
        k = (public_key['n'].bit_length() + 7) // 8
        return c.to_bytes(k, 'big')
    
    def rsa_decrypt(self, ciphertext: bytes, private_key: dict) -> bytes:
        """
        Decifração RSA com OAEP
        """
        # Converte para inteiro
        c = int.from_bytes(ciphertext, 'big')
        
        # Decifração RSA: m = c^d mod n
        m = pow(c, private_key['d'], private_key['n'])
        
        # Converte para bytes
        k = (private_key['n'].bit_length() + 7) // 8
        encoded = m.to_bytes(k, 'big')
        
        # OAEP decoding
        return self.oaep_decode(encoded, private_key['n'])
    
    def sha3_hash(self, data: bytes) -> bytes:
        """
        Calcula hash SHA-3 dos dados
        """
        return hashlib.sha3_256(data).digest()
    
    def sign_message(self, message: bytes, private_key: dict) -> str:
        """
        Assina uma mensagem usando RSA
        Returns: assinatura em base64
        """
        print("Assinando mensagem...")
        
        # 1. Calcula hash da mensagem
        message_hash = self.sha3_hash(message)
        print(f"Hash da mensagem: {message_hash.hex()}")
        
        # 2. Assina o hash (cifra com chave privada)
        # Converte hash para inteiro
        hash_int = int.from_bytes(message_hash, 'big')
        
        # Assina: s = hash^d mod n
        signature_int = pow(hash_int, private_key['d'], private_key['n'])
        
        # Converte para bytes
        k = (private_key['n'].bit_length() + 7) // 8
        signature_bytes = signature_int.to_bytes(k, 'big')
        
        # 3. Formata resultado em JSON + Base64
        signature_data = {
            'message': base64.b64encode(message).decode('utf-8'),
            'signature': base64.b64encode(signature_bytes).decode('utf-8'),
            'algorithm': 'RSA-SHA3-256',
            'key_size': private_key['n'].bit_length()
        }
        
        result = base64.b64encode(json.dumps(signature_data).encode()).decode('utf-8')
        print("Mensagem assinada com sucesso!")
        
        return result
    
    def verify_signature(self, signed_data: str, public_key: dict) -> bool:
        """
        Verifica assinatura de uma mensagem
        Args:
            signed_data: dados assinados em base64
            public_key: chave pública para verificação
        Returns: True se assinatura válida, False caso contrário
        """
        try:
            print("Verificando assinatura...")
            
            # 1. Parse do documento assinado (Base64 decode)
            decoded_data = base64.b64decode(signed_data.encode())
            signature_data = json.loads(decoded_data.decode())
            
            # Extrai componentes
            message = base64.b64decode(signature_data['message'])
            signature_bytes = base64.b64decode(signature_data['signature'])
            
            print(f"Algoritmo: {signature_data['algorithm']}")
            print(f"Tamanho da chave: {signature_data['key_size']} bits")
            
            # 2. Decifra a assinatura (verifica com chave pública)
            signature_int = int.from_bytes(signature_bytes, 'big')
            
            # Verifica: hash = s^e mod n
            decrypted_hash_int = pow(signature_int, public_key['e'], public_key['n'])
            
            # Converte para bytes (padding com zeros à esquerda se necessário)
            hash_length = 32  # SHA3-256 produz 32 bytes
            decrypted_hash = decrypted_hash_int.to_bytes(hash_length, 'big')
            
            # 3. Calcula hash da mensagem original
            calculated_hash = self.sha3_hash(message)
            
            print(f"Hash calculado: {calculated_hash.hex()}")
            print(f"Hash da assinatura: {decrypted_hash.hex()}")
            
            # 4. Compara hashes
            is_valid = calculated_hash == decrypted_hash
            
            if is_valid:
                print("✓ Assinatura VÁLIDA!")
            else:
                print("✗ Assinatura INVÁLIDA!")
                
            return is_valid
            
        except Exception as e:
            print(f"Erro na verificação: {e}")
            return False
    
    def save_keys(self, public_key: dict, private_key: dict, prefix: str = "key"):
        """
        Salva chaves em arquivos
        """
        with open(f"{prefix}_public.json", 'w') as f:
            json.dump(public_key, f, indent=2)
            
        with open(f"{prefix}_private.json", 'w') as f:
            json.dump(private_key, f, indent=2)
            
        print(f"Chaves salvas em {prefix}_public.json e {prefix}_private.json")
    
    def load_keys(self, prefix: str = "key") -> Tuple[dict, dict]:
        """
        Carrega chaves de arquivos
        """
        with open(f"{prefix}_public.json", 'r') as f:
            public_key = json.load(f)
            
        with open(f"{prefix}_private.json", 'r') as f:
            private_key = json.load(f)
            
        return public_key, private_key


def main():
    """
    Função principal - demonstra uso do sistema
    """
    rsa_system = RSASignatureSystem()
    
    print("=== Sistema de Assinatura RSA ===\n")
    
    while True:
        print("\nEscolha uma opção:")
        print("1. Gerar par de chaves")
        print("2. Assinar mensagem")
        print("3. Verificar assinatura")
        print("4. Teste com cifração/decifração")
        print("5. Sair")
        
        choice = input("\nOpção: ").strip()
        
        if choice == '1':
            # Gerar chaves
            public_key, private_key = rsa_system.generate_keypair()
            rsa_system.save_keys(public_key, private_key)
            
        elif choice == '2':
            # Assinar mensagem
            try:
                public_key, private_key = rsa_system.load_keys()
                
                message = input("Digite a mensagem para assinar: ").encode('utf-8')
                signature = rsa_system.sign_message(message, private_key)
                
                # Salva assinatura em arquivo
                with open('message_signed.txt', 'w') as f:
                    f.write(signature)
                    
                print("Assinatura salva em 'message_signed.txt'")
                
            except FileNotFoundError:
                print("Erro: Chaves não encontradas. Gere as chaves primeiro.")
                
        elif choice == '3':
            # Verificar assinatura
            try:
                public_key, _ = rsa_system.load_keys()
                
                filename = input("Nome do arquivo com assinatura (ou pressione Enter para 'message_signed.txt'): ").strip()
                if not filename:
                    filename = 'message_signed.txt'
                    
                with open(filename, 'r') as f:
                    signed_data = f.read().strip()
                    
                rsa_system.verify_signature(signed_data, public_key)
                
            except FileNotFoundError:
                print("Erro: Arquivo não encontrado.")
            except Exception as e:
                print(f"Erro: {e}")
                
        elif choice == '4':
            # Teste de cifração/decifração
            try:
                public_key, private_key = rsa_system.load_keys()
                
                message = input("Digite mensagem para cifrar: ").encode('utf-8')
                
                print("Cifrando mensagem...")
                ciphertext = rsa_system.rsa_encrypt(message, public_key)
                print(f"Texto cifrado (hex): {ciphertext.hex()}")
                
                print("Decifrando mensagem...")
                decrypted = rsa_system.rsa_decrypt(ciphertext, private_key)
                print(f"Texto decifrado: {decrypted.decode('utf-8')}")
                
            except FileNotFoundError:
                print("Erro: Chaves não encontradas. Gere as chaves primeiro.")
            except Exception as e:
                print(f"Erro: {e}")
                
        elif choice == '5':
            print("Saindo...")
            break
            
        else:
            print("Opção inválida!")


if __name__ == "__main__":
    main()