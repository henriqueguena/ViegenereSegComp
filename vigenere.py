alfabeto = "abcdefghijklmnopqrstuvwxyz"
chave = "teste"
plaintext = "a inteligencia artificial tem revolucionado diversos setores da sociedade moderna.desde a medicina ate a agricultura, algoritmos sao empregados para prever comportamentos,automatizar tarefas repetitivas e melhorar processos de decisao. no entanto, com os avançosvem tambem desafios eticos importantes, como a privacidade dos dados, o viés nos algoritmose a substituicao da mao de obra humana. por isso, o desenvolvimento e uso responsavel datecnologia se torna cada vez mais crucial para garantir beneficios sustentaveis a longo prazo."
contador = 0
cifra = ''
frequencia_portugues = [
    14.63,  # A
    1.04,   # B
    3.88,   # C
    4.99,   # D
    12.57,  # E
    1.02,   # F
    1.30,   # G
    1.28,   # H
    6.18,   # I
    0.40,   # J
    0.02,   # K
    2.78,   # L
    4.74,   # M
    5.05,   # N
    10.73,  # O
    2.52,   # P
    1.20,   # Q
    6.53,   # R
    7.81,   # S
    4.34,   # T
    4.63,   # U
    1.67,   # V
    0.01,   # W
    0.21,   # X
    0.01,   # Y
    0.47    # Z
]

import re
import unicodedata

def normalizar(texto):
    # Remove acentos
    texto_sem_acentos = ''.join(
        c for c in unicodedata.normalize('NFD', texto)
        if unicodedata.category(c) != 'Mn'
    )
    # Converte para minúsculas
    return texto_sem_acentos.lower()

plaintext = normalizar(plaintext)


for i in plaintext:
    if i in alfabeto:
        cifra = cifra + alfabeto[(alfabeto.index(i) + alfabeto.index(chave[contador]))%26]
        if contador + 1 < len(chave):
            contador = contador + 1
        else:
            contador = 0
    else:
        cifra = cifra + i
print(cifra)

def limpar_texto(texto):
    # Remove tudo que não for letra (a-z)
    texto_apenas_letras = re.sub(r'[^a-z]', '', texto)
    return texto_apenas_letras

cifra_limpa = limpar_texto(cifra)

matriz_trincas = []
for n in range(len(cifra_limpa)-2):
    new = True
    for i in matriz_trincas:
        if cifra_limpa[n:n+3] == i[0]:
            new = False
            break
    if new:
        matriz_trincas.append([cifra_limpa[n:n+3],cifra_limpa.count(cifra_limpa[n:n+3])])

matriz_trincas.sort(key=lambda x: x[1], reverse=True)

top_20 = matriz_trincas[0:]

resultado = []

for item in top_20:
    trinca = item[0]
    freq = item[1]
    
    # Encontrar posições onde a trinca aparece
    posicoes = []
    for i in range(len(cifra_limpa) - 2):
        if cifra_limpa[i:i+3] == trinca:
            posicoes.append(i)
    
    # Calcular espaçamentos
    espacamentos = []
    for i in range(1, len(posicoes)):
        espacamentos.append(posicoes[i] - posicoes[i-1])
    
    if espacamentos:
        menor_espaco = min(espacamentos)
    else:
        menor_espaco = None
    
    resultado.append([trinca, freq, menor_espaco])

# 5. Exibir o resultado
for item in resultado:
    print(f"Trinca: {item[0]} | Ocorrências: {item[1]} | Menor espaçamento: {item[2]}")

def fatores_menores_que_26(n):
    fatores = []
    for i in range(2, 300):  # de 2 a 25
        if n % i == 0:
            fatores.append(i)
    return fatores


frequencia_fatores = {}

for item in resultado:  # resultado = lista de [trinca, freq, menor_espacamento]
    menor_espacamento = item[2]
    
    if menor_espacamento is not None and menor_espacamento > 1:
        fatores = fatores_menores_que_26(menor_espacamento)
        
        for f in fatores:
            if f in frequencia_fatores:
                frequencia_fatores[f] += 1
            else:
                frequencia_fatores[f] = 1


# Ordenar os fatores pela frequência decrescente
fatores_ordenados = sorted(frequencia_fatores.items(), key=lambda x: x[1], reverse=True)

print("Fator | Frequência")
print("------------------")
for fator, freq in fatores_ordenados:
    print(f"{fator:5} | {freq}")

print("Top 5 fatores mais frequentes:")
for idx, (fator, freq) in enumerate(fatores_ordenados[:5]):
    print(f"{idx+1}. Fator: {fator} | Frequência: {freq}")
escolha = int(input("Escolha 1, 2, 3, 4 ou 5: "))
if 1 <= escolha <= 5:
    fator_escolhido = fatores_ordenados[escolha - 1][0]
    print(f"Fator escolhido pelo usuário: {fator_escolhido}")
else:
    print("Escolha inválida.")
    exit()

from collections import Counter

def frequencia_letras(texto):
    total = len(texto)
    contagem = Counter(texto)
    frequencias = {}
    for letra in alfabeto:
        frequencias[letra] = (contagem[letra] / total * 100) if letra in contagem else 0
    return frequencias

def deslocar_letra(letra, deslocamento):
    return alfabeto[(alfabeto.index(letra) + deslocamento) % 26]

def aplicar_deslocamento_no_grupo(grupo, deslocamento):
    decifrado = ''
    for letra in grupo:
        decifrado += alfabeto[(alfabeto.index(letra) - deslocamento) % 26]
    return decifrado

print(f"\n=== Ajuste interativo da chave para fator escolhido: {fator_escolhido} ===")

chave_sugerida = ''

for posicao in range(fator_escolhido):
    # Pega só as letras da cifra no índice da letra da chave
    grupo = ''.join(cifra_limpa[i] for i in range(posicao, len(cifra_limpa), fator_escolhido))

    print(f"\n--- Ajustando posição {posicao + 1} da chave ---")
    
    freq_grupo_original = frequencia_letras(grupo)
    letra_mais_frequente = max(freq_grupo_original.items(), key=lambda x: x[1])[0]
    deslocamento = (alfabeto.index(letra_mais_frequente) - alfabeto.index('e')) % 26

    while True:
        decifrado = aplicar_deslocamento_no_grupo(grupo, deslocamento)
        freq_decifrado = frequencia_letras(decifrado)

        print("Letra | Freq decifrado (%) | Freq PT-BR (%)")
        print("-------------------------------------------")
        for i, letra in enumerate(alfabeto):
            print(f"{letra:5} | {freq_decifrado[letra]:17.2f} | {frequencia_portugues[i]:14.2f}")

        letra_sugerida = deslocar_letra('a', -deslocamento)
        print(f"\nDeslocamento atual: {deslocamento} | Letra sugerida para chave: '{letra_sugerida}'")

        ajuste = input("Ajustar (D = direita, E = esquerda, Enter = aceitar): ").strip().lower()
        if ajuste == 'd':
            deslocamento = (deslocamento + 1) % 26
        elif ajuste == 'e':
            deslocamento = (deslocamento - 1) % 26
        else:
            break

    chave_sugerida += letra_sugerida

print(f"\nChave final sugerida pelo usuário: {chave_sugerida}")

def decifrar(cifra, chave):
    plaintext = ''
    contador = 0
    for c in cifra:
        if c in alfabeto:
            letra_chave = chave[contador % len(chave)]
            deslocamento = alfabeto.index(letra_chave)
            indice = (alfabeto.index(c) - deslocamento) % 26
            plaintext += alfabeto[indice]
            contador += 1
        else:
            plaintext += c  # mantém espaços, pontuação etc.
    return plaintext

print("\nChave final ajustada:", ''.join(chave_sugerida))
texto_decifrado = decifrar(cifra, chave_sugerida)
print("\nTexto decifrado:\n")
print(texto_decifrado)
