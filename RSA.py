#!/usr/bin/env python3

import hashlib
import os
import random
import base64
import json
from typing import Tuple, Optional

class SistemaAssinaturaRSA:
    def __init__(self):
        self.tamanho_chave = 1024  # bits
        
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
    
    def gerar_primo(self, bits: int) -> int:
        """
        Gera um número primo com o número especificado de bits
        """
        while True:
            # Gera número ímpar aleatório com bits especificados
            candidato = random.getrandbits(bits)
            candidato |= (1 << bits - 1) | 1  # Garante que tem bits bits e é ímpar
            
            if self.miller_rabin(candidato):
                return candidato
    
    def mdc_estendido(self, a: int, b: int) -> Tuple[int, int, int]:
        """
        Algoritmo euclidiano estendido
        Returns: (mdc, x, y) onde ax + by = mdc(a, b)
        """
        if a == 0:
            return b, 0, 1
        mdc, x1, y1 = self.mdc_estendido(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return mdc, x, y
    
    def inverso_modular(self, a: int, m: int) -> int:
        """
        Calcula o inverso modular de a mod m
        """
        mdc, x, _ = self.mdc_estendido(a, m)
        if mdc != 1:
            raise ValueError("Inverso modular não existe")
        return (x % m + m) % m
    
    def gerar_par_chaves(self) -> Tuple[dict, dict]:
        """
        Gera par de chaves RSA (pública e privada)
        Returns: (chave_publica, chave_privada)
        """
        print("Gerando chaves RSA...")
        
        # Gera dois primos grandes
        p = self.gerar_primo(self.tamanho_chave // 2)
        q = self.gerar_primo(self.tamanho_chave // 2)
        
        # Calcula n e φ(n)
        n = p * q
        phi_n = (p - 1) * (q - 1)
        
        # Escolhe e (geralmente 65537)
        e = 65537
        
        # Calcula d (inverso de e mod φ(n))
        d = self.inverso_modular(e, phi_n)
        
        chave_publica = {'n': n, 'e': e}
        chave_privada = {'n': n, 'd': d, 'p': p, 'q': q}
        
        print(f"Chaves geradas com sucesso!")
        print(f"Tamanho da chave: {n.bit_length()} bits")
        
        return chave_publica, chave_privada
    
    def mgf1(self, semente: bytes, comprimento: int) -> bytes:
        """
        Função de Geração de Máscara 1 (MGF1) baseada em SHA-256
        """
        if comprimento >= (1 << 32) * 32:
            raise ValueError("máscara muito longa")
            
        T = b""
        contador = 0
        while len(T) < comprimento:
            C = contador.to_bytes(4, 'big')
            T += hashlib.sha256(semente + C).digest()
            contador += 1
            
        return T[:comprimento]
    
    def codificar_oaep(self, mensagem: bytes, n: int, rotulo: bytes = b"") -> bytes:
        """
        Codificação OAEP (Optimal Asymmetric Encryption Padding)
        """
        k = (n.bit_length() + 7) // 8  # Tamanho em bytes
        tamanho_msg = len(mensagem)
        
        # Verifica se a mensagem não é muito longa
        if tamanho_msg > k - 2 * 32 - 2:  # 32 = tamanho do hash SHA-256
            raise ValueError("mensagem muito longa")
            
        # Calcula hash do rótulo
        hash_rotulo = hashlib.sha256(rotulo).digest()
        
        # Preenchimento
        tamanho_ps = k - tamanho_msg - 2 * 32 - 2
        ps = b'\x00' * tamanho_ps
        
        # DB = lHash || PS || 0x01 || M
        db = hash_rotulo + ps + b'\x01' + mensagem
        
        # Gera semente aleatória
        semente = os.urandom(32)
        
        # dbMask = MGF(semente, k - hLen - 1)
        mascara_db = self.mgf1(semente, k - 32 - 1)
        
        # maskedDB = DB ⊕ dbMask
        db_mascarado = bytes(a ^ b for a, b in zip(db, mascara_db))
        
        # seedMask = MGF(maskedDB, hLen)
        mascara_semente = self.mgf1(db_mascarado, 32)
        
        # maskedSeed = semente ⊕ seedMask
        semente_mascarada = bytes(a ^ b for a, b in zip(semente, mascara_semente))
        
        # EM = 0x00 || maskedSeed || maskedDB
        em = b'\x00' + semente_mascarada + db_mascarado
        
        return em
    
    def decodificar_oaep(self, mensagem_codificada: bytes, n: int, rotulo: bytes = b"") -> bytes:
        """
        Decodificação OAEP
        """
        k = (n.bit_length() + 7) // 8
        
        if len(mensagem_codificada) != k or k < 2 * 32 + 2:
            raise ValueError("erro na decifração")
            
        # Separa componentes
        y = mensagem_codificada[0]
        semente_mascarada = mensagem_codificada[1:33]
        db_mascarado = mensagem_codificada[33:]
        
        if y != 0:
            raise ValueError("erro na decifração")
            
        # Recupera semente
        mascara_semente = self.mgf1(db_mascarado, 32)
        semente = bytes(a ^ b for a, b in zip(semente_mascarada, mascara_semente))
        
        # Recupera DB
        mascara_db = self.mgf1(semente, k - 32 - 1)
        db = bytes(a ^ b for a, b in zip(db_mascarado, mascara_db))
        
        # Verifica lHash
        hash_rotulo = hashlib.sha256(rotulo).digest()
        hash_rotulo_primo = db[:32]
        
        if hash_rotulo != hash_rotulo_primo:
            raise ValueError("erro na decifração")
            
        # Encontra separador 0x01
        i = 32
        while i < len(db) and db[i] == 0:
            i += 1
            
        if i >= len(db) or db[i] != 1:
            raise ValueError("erro na decifração")
            
        return db[i + 1:]
    
    def cifrar_rsa(self, mensagem: bytes, chave_publica: dict) -> bytes:
        """
        Cifração RSA com OAEP
        """
        # Codificação OAEP
        codificado = self.codificar_oaep(mensagem, chave_publica['n'])
        
        # Converte para inteiro
        m = int.from_bytes(codificado, 'big')
        
        # Cifração RSA: c = m^e mod n
        c = pow(m, chave_publica['e'], chave_publica['n'])
        
        # Converte para bytes
        k = (chave_publica['n'].bit_length() + 7) // 8
        return c.to_bytes(k, 'big')
    
    def decifrar_rsa(self, texto_cifrado: bytes, chave_privada: dict) -> bytes:
        """
        Decifração RSA com OAEP
        """
        # Converte para inteiro
        c = int.from_bytes(texto_cifrado, 'big')
        
        # Decifração RSA: m = c^d mod n
        m = pow(c, chave_privada['d'], chave_privada['n'])
        
        # Converte para bytes
        k = (chave_privada['n'].bit_length() + 7) // 8
        codificado = m.to_bytes(k, 'big')
        
        # Decodificação OAEP
        return self.decodificar_oaep(codificado, chave_privada['n'])
    
    def hash_sha3(self, dados: bytes) -> bytes:
        """
        Calcula hash SHA-3 dos dados
        """
        return hashlib.sha3_256(dados).digest()
    
    def assinar_mensagem(self, mensagem: bytes, chave_privada: dict) -> str:
        """
        Assina uma mensagem usando RSA
        Returns: assinatura em base64
        """
        print("Assinando mensagem...")
        
        # 1. Calcula hash da mensagem
        hash_mensagem = self.hash_sha3(mensagem)
        print(f"Hash da mensagem: {hash_mensagem.hex()}")
        
        # 2. Assina o hash (cifra com chave privada)
        # Converte hash para inteiro
        hash_int = int.from_bytes(hash_mensagem, 'big')
        
        # Assina: s = hash^d mod n
        assinatura_int = pow(hash_int, chave_privada['d'], chave_privada['n'])
        
        # Converte para bytes
        k = (chave_privada['n'].bit_length() + 7) // 8
        bytes_assinatura = assinatura_int.to_bytes(k, 'big')
        
        # 3. Formata resultado em JSON + Base64
        dados_assinatura = {
            'mensagem': base64.b64encode(mensagem).decode('utf-8'),
            'assinatura': base64.b64encode(bytes_assinatura).decode('utf-8'),
            'algoritmo': 'RSA-SHA3-256',
            'tamanho_chave': chave_privada['n'].bit_length()
        }
        
        resultado = base64.b64encode(json.dumps(dados_assinatura).encode()).decode('utf-8')
        print("Mensagem assinada com sucesso!")
        
        return resultado
    
    def verificar_assinatura(self, dados_assinados: str, chave_publica: dict) -> bool:
        """
        Verifica assinatura de uma mensagem
        Args:
            dados_assinados: dados assinados em base64
            chave_publica: chave pública para verificação
        Returns: True se assinatura válida, False caso contrário
        """
        try:
            print("Verificando assinatura...")
            
            # 1. Análise do documento assinado (Base64 decode)
            dados_decodificados = base64.b64decode(dados_assinados.encode())
            dados_assinatura = json.loads(dados_decodificados.decode())
            
            # Extrai componentes
            mensagem = base64.b64decode(dados_assinatura['mensagem'])
            bytes_assinatura = base64.b64decode(dados_assinatura['assinatura'])
            
            print(f"Algoritmo: {dados_assinatura['algoritmo']}")
            print(f"Tamanho da chave: {dados_assinatura['tamanho_chave']} bits")
            
            # 2. Decifra a assinatura (verifica com chave pública)
            assinatura_int = int.from_bytes(bytes_assinatura, 'big')
            
            # Verifica: hash = s^e mod n
            hash_decifrado_int = pow(assinatura_int, chave_publica['e'], chave_publica['n'])
            
            # Converte para bytes (preenchimento com zeros à esquerda se necessário)
            tamanho_hash = 32  # SHA3-256 produz 32 bytes
            hash_decifrado = hash_decifrado_int.to_bytes(tamanho_hash, 'big')
            
            # 3. Calcula hash da mensagem original
            hash_calculado = self.hash_sha3(mensagem)
            
            print(f"Hash calculado: {hash_calculado.hex()}")
            print(f"Hash da assinatura: {hash_decifrado.hex()}")
            
            # 4. Compara hashes
            eh_valida = hash_calculado == hash_decifrado
            
            if eh_valida:
                print("✓ Assinatura VÁLIDA!")
            else:
                print("✗ Assinatura INVÁLIDA!")
                
            return eh_valida
            
        except Exception as e:
            print(f"Erro na verificação: {e}")
            return False
    
    def salvar_chaves(self, chave_publica: dict, chave_privada: dict, prefixo: str = "key"):
        """
        Salva chaves em arquivos
        """
        with open(f"{prefixo}_public.json", 'w') as f:
            json.dump(chave_publica, f, indent=2)
            
        with open(f"{prefixo}_private.json", 'w') as f:
            json.dump(chave_privada, f, indent=2)
            
        print(f"Chaves salvas em {prefixo}_public.json e {prefixo}_private.json")
    
    def carregar_chaves(self, prefixo: str = "key") -> Tuple[dict, dict]:
        """
        Carrega chaves de arquivos
        """
        with open(f"{prefixo}_public.json", 'r') as f:
            chave_publica = json.load(f)
            
        with open(f"{prefixo}_private.json", 'r') as f:
            chave_privada = json.load(f)
            
        return chave_publica, chave_privada


def main():
    """
    Função principal - demonstra uso do sistema
    """
    sistema_rsa = SistemaAssinaturaRSA()
    
    print("=== Sistema de Assinatura RSA ===\n")
    
    while True:
        print("\nEscolha uma opção:")
        print("1. Gerar par de chaves")
        print("2. Assinar mensagem")
        print("3. Verificar assinatura")
        print("4. Teste com cifração/decifração")
        print("5. Sair")
        
        opcao = input("\nOpção: ").strip()
        
        if opcao == '1':
            # Gerar chaves
            chave_publica, chave_privada = sistema_rsa.gerar_par_chaves()
            sistema_rsa.salvar_chaves(chave_publica, chave_privada)
            
        elif opcao == '2':
            # Assinar mensagem
            try:
                chave_publica, chave_privada = sistema_rsa.carregar_chaves()
                
                mensagem = input("Digite a mensagem para assinar: ").encode('utf-8')
                assinatura = sistema_rsa.assinar_mensagem(mensagem, chave_privada)
                
                # Salva assinatura em arquivo
                with open('message_signed.txt', 'w') as f:
                    f.write(assinatura)
                    
                print("Assinatura salva em 'message_signed.txt'")
                
            except FileNotFoundError:
                print("Erro: Chaves não encontradas. Gere as chaves primeiro.")
                
        elif opcao == '3':
            # Verificar assinatura
            try:
                chave_publica, _ = sistema_rsa.carregar_chaves()
                
                nome_arquivo = input("Nome do arquivo com assinatura (ou pressione Enter para 'message_signed.txt'): ").strip()
                if not nome_arquivo:
                    nome_arquivo = 'message_signed.txt'
                    
                with open(nome_arquivo, 'r') as f:
                    dados_assinados = f.read().strip()
                    
                sistema_rsa.verificar_assinatura(dados_assinados, chave_publica)
                
            except FileNotFoundError:
                print("Erro: Arquivo não encontrado.")
            except Exception as e:
                print(f"Erro: {e}")
                
        elif opcao == '4':
            # Teste de cifração/decifração
            try:
                chave_publica, chave_privada = sistema_rsa.carregar_chaves()
                
                mensagem = input("Digite mensagem para cifrar: ").encode('utf-8')
                
                print("Cifrando mensagem...")
                texto_cifrado = sistema_rsa.cifrar_rsa(mensagem, chave_publica)
                print(f"Texto cifrado (hex): {texto_cifrado.hex()}")
                
                print("Decifrando mensagem...")
                decifrado = sistema_rsa.decifrar_rsa(texto_cifrado, chave_privada)
                print(f"Texto decifrado: {decifrado.decode('utf-8')}")
                
            except FileNotFoundError:
                print("Erro: Chaves não encontradas. Gere as chaves primeiro.")
            except Exception as e:
                print(f"Erro: {e}")
                
        elif opcao == '5':
            print("Saindo...")
            break
            
        else:
            print("Opção inválida!")


if __name__ == "__main__":
    main()
