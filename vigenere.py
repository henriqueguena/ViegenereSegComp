import re
import unicodedata

alfabeto = "abcdefghijklmnopqrstuvwxyz"
chave_pt = "chave"
chave_en = "keyst"
plaintext_portugues = """
A segurança computacional é uma disciplina essencial dentro da tecnologia da informação, cuja função principal é proteger sistemas, redes, programas e dados contra ameaças internas e externas que possam comprometer sua integridade, confidencialidade e disponibilidade. Em um mundo cada vez mais digitalizado, onde transações bancárias, comunicações pessoais, registros médicos, operações empresariais e decisões governamentais dependem fortemente de sistemas informatizados, a segurança computacional tornou-se um pilar indispensável para o funcionamento seguro e eficiente da sociedade moderna.

Com o avanço da tecnologia, surgiram novas oportunidades, mas também novos riscos. A expansão da internet, o aumento do uso de dispositivos móveis, o armazenamento em nuvem e a popularização da Internet das Coisas (IoT) ampliaram a superfície de ataque e trouxeram consigo desafios complexos. Cibercriminosos, hackers e agentes maliciosos utilizam técnicas cada vez mais sofisticadas, como malwares, ransomwares, phishing, ataques de negação de serviço (DDoS) e engenharia social, para explorar vulnerabilidades e obter acesso não autorizado a dados sensíveis ou causar prejuízos a indivíduos e organizações.

Nesse contexto, a segurança computacional vai muito além da simples instalação de antivírus ou do uso de senhas fortes. Ela envolve um conjunto abrangente de práticas e tecnologias que incluem criptografia, autenticação multifator, sistemas de detecção e prevenção de intrusos, firewalls, atualizações regulares de software, backups frequentes e monitoramento constante de redes e dispositivos. Além disso, políticas de segurança bem definidas, treinamento de usuários e uma cultura organizacional voltada à proteção da informação são elementos cruciais para a prevenção de incidentes.

Outro aspecto importante da segurança computacional é o cumprimento de normas e regulamentações que visam proteger dados pessoais e sensíveis, como a Lei Geral de Proteção de Dados (LGPD) no Brasil e o Regulamento Geral sobre a Proteção de Dados (GDPR) na União Europeia. Tais legislações impõem obrigações às empresas quanto à coleta, armazenamento, tratamento e compartilhamento de informações, promovendo maior transparência e responsabilidade.

A segurança computacional é, portanto, um campo dinâmico e estratégico, que exige atualização constante diante da rápida evolução das ameaças digitais. Profissionais da área precisam combinar conhecimentos técnicos com capacidade analítica e visão crítica para antecipar riscos, implementar soluções eficazes e garantir que a infraestrutura digital continue operando de maneira segura. Em um cenário onde a informação é um dos ativos mais valiosos, proteger os dados é proteger pessoas, negócios e instituições.
"""

frequencia_portugues = [
    14.63, 1.04, 3.88, 4.99, 12.57, 1.02, 1.30, 1.28, 6.18,
    0.40, 0.02, 2.78, 4.74, 5.05, 10.73, 2.52, 1.20, 6.53,
    7.81, 4.34, 4.63, 1.67, 0.01, 0.21, 0.01, 0.47
]

frequencia_ingles = [
    8.16, 1.49, 2.78, 4.25, 12.70, 2.22, 2.01, 6.09, 6.96,
    0.15, 0.77, 4.02, 2.40, 6.74, 7.50, 1.92, 0.09, 5.98,
    6.32, 9.05, 2.75, 0.97, 2.36, 0.15, 1.97, 0.07
]

plaintext_ingles = """
Computational security is an essential discipline within information technology, whose main function is to protect systems, networks, programs, and data against internal and external threats that could compromise their integrity, confidentiality, and availability. In an increasingly digitalized world, where banking transactions, personal communications, medical records, business operations, and government decisions heavily rely on computerized systems, computational security has become an indispensable pillar for the safe and efficient functioning of modern society.

With the advancement of technology, new opportunities have emerged, but so have new risks. The expansion of the internet, the increased use of mobile devices, cloud storage, and the popularization of the Internet of Things (IoT) have broadened the attack surface and brought with them complex challenges. Cybercriminals, hackers, and malicious agents use increasingly sophisticated techniques, such as malware, ransomware, phishing, denial-of-service (DDoS) attacks, and social engineering, to exploit vulnerabilities and gain unauthorized access to sensitive data or cause harm to individuals and organizations.

In this context, computational security goes far beyond simply installing antivirus software or using strong passwords. It involves a comprehensive set of practices and technologies that include encryption, multi-factor authentication, intrusion detection and prevention systems, firewalls, regular software updates, frequent backups, and constant monitoring of networks and devices. Additionally, well-defined security policies, user training, and an organizational culture focused on information protection are crucial elements for preventing incidents.

Another important aspect of computational security is compliance with rules and regulations aimed at protecting personal and sensitive data, such as the General Data Protection Law (LGPD) in Brazil and the General Data Protection Regulation (GDPR) in the European Union. These regulations impose obligations on companies regarding the collection, storage, processing, and sharing of information, promoting greater transparency and accountability.

Therefore, computational security is a dynamic and strategic field that requires constant updates in the face of the rapid evolution of digital threats. Professionals in this area must combine technical knowledge with analytical skills and critical thinking to anticipate risks, implement effective solutions, and ensure that digital infrastructure continues to operate securely. In a scenario where information is one of the most valuable assets, protecting data means protecting people, businesses, and institutions.
"""
def normalizar(texto):
    texto_sem_acentos = ''.join(
        c for c in unicodedata.normalize('NFD', texto)
        if unicodedata.category(c) != 'Mn'
    )
    return texto_sem_acentos.lower()

def limpar_texto(texto):
    return re.sub(r'[^a-z]', '', texto)

def calcular_frequencia_letras(texto):
    contador = [0] * 26
    total = 0
    for c in texto:
        if c in alfabeto:
            idx = alfabeto.index(c)
            contador[idx] += 1
            total += 1
    return [(x / total * 100) if total > 0 else 0 for x in contador]

def exibir_frequencias_linha(frequencias, titulo="Frequências"):
    print(f"\n{titulo}:")
    print("A     B     C     D     E     F     G     H     I     J     K     L     M     N     O     P     Q     R     S     T     U     V     W     X     Y     Z")
    print("-" * 130)
    print(' '.join(f"{freq:5.2f}" for freq in frequencias))

def cifrar_vigenere(texto, chave):
    contador = 0
    cifra = ''
    for i in texto:
        if i in alfabeto:
            cifra += alfabeto[(alfabeto.index(i) + alfabeto.index(chave[contador])) % 26]
            contador = (contador + 1) % len(chave)
        else:
            cifra += i
    return cifra

def encontrar_trincas(cifra_limpa):
    matriz_trincas = []
    for n in range(len(cifra_limpa) - 2):
        trinca = cifra_limpa[n:n + 3]
        encontrado = any(item[0] == trinca for item in matriz_trincas)
        if not encontrado:
            matriz_trincas.append([trinca, cifra_limpa.count(trinca)])

    matriz_trincas.sort(key=lambda x: x[1], reverse=True)

    resultado = []
    for item in matriz_trincas:
        trinca = item[0]
        freq = item[1]
        posicoes = [i for i in range(len(cifra_limpa) - 2) if cifra_limpa[i:i + 3] == trinca]
        espacamentos = [posicoes[i] - posicoes[i - 1] for i in range(1, len(posicoes))]
        menor_espaco = min(espacamentos) if espacamentos else None
        resultado.append([trinca, freq, menor_espaco])
    return resultado

def fatores_menores_que_26(n):
    return [i for i in range(2, 26) if n % i == 0]

def obter_fator_mais_frequente(resultado):
    frequencia_fatores = {}
    for item in resultado:
        if item[2] and item[2] > 1:
            fatores = fatores_menores_que_26(item[2])
            for f in fatores:
                frequencia_fatores[f] = frequencia_fatores.get(f, 0) + 1

    fatores_ordenados = sorted(frequencia_fatores.items(), key=lambda x: x[1], reverse=True)
    return fatores_ordenados

def separar_texto_por_posicao(texto, tamanho_chave):
    grupos = [[] for _ in range(tamanho_chave)]
    for i, c in enumerate(texto):
        if c in alfabeto:
            grupos[i % tamanho_chave].append(c)
    return [''.join(g) for g in grupos]

def deslocar_frequencias(freq, deslocamento):
    return freq[deslocamento:] + freq[:deslocamento]

def decifrar_vigenere(texto_cifrado, chave):
    texto_decifrado = ''
    contador = 0
    for c in texto_cifrado:
        if c in alfabeto:
            pos_letra = (alfabeto.index(c) - alfabeto.index(chave[contador % len(chave)].lower())) % 26
            texto_decifrado += alfabeto[pos_letra]
            contador += 1
        else:
            texto_decifrado += c
    return texto_decifrado

def processar_texto(texto, chave, freq_esperada, idioma):
    print(f"\n=== PROCESSANDO TEXTO EM {idioma.upper()} ===")
    texto_norm = normalizar(texto)
    cifra = cifrar_vigenere(texto_norm, chave)
    print(f'texto cifrado:{cifra}')
    cifra_limpa = limpar_texto(cifra)
    resultado = encontrar_trincas(cifra_limpa)
    fatores = obter_fator_mais_frequente(resultado)

    print("\nTop 5 fatores mais frequentes:")
    for idx, (fator, freq) in enumerate(fatores[:5]):
        print(f"{idx + 1}. Fator: {fator} | Frequência: {freq}")

    escolha = int(input("\nEscolha 1, 2, 3, 4 ou 5: "))
    fator_escolhido = fatores[escolha - 1][0]

    grupos = separar_texto_por_posicao(cifra_limpa, fator_escolhido)
    chave_descoberta = ['?'] * fator_escolhido

    for posicao in range(fator_escolhido):
        grupo = grupos[posicao]
        if not grupo:
            continue

        print(f"\nPOSIÇÃO {posicao + 1} DA CHAVE")
        freq_posicao = calcular_frequencia_letras(grupo)
        exibir_frequencias_linha(freq_posicao, "Frequências observadas")
        exibir_frequencias_linha(freq_esperada, "Frequências esperadas")

        letra_mais_freq = alfabeto[freq_posicao.index(max(freq_posicao))]
        letra_referencia = 'e' if idioma == 'en' else 'a'
        sugestao = alfabeto[(alfabeto.index(letra_mais_freq) - alfabeto.index(letra_referencia)) % 26]
        print(f"Sugestão: '{letra_mais_freq.upper()}' -> '{sugestao.upper()}'")

        while True:
            letra_chave = input(f"Letra para posição {posicao + 1} (Enter = '{sugestao.upper()}'): ").upper()
            if letra_chave == "":
                letra_chave = sugestao.upper()
            if letra_chave.lower() not in alfabeto:
                print("Letra inválida.")
                continue
            deslocamento = alfabeto.index(letra_chave.lower())
            freq_deslocada = deslocar_frequencias(freq_posicao, deslocamento)
            exibir_frequencias_linha(freq_deslocada, f"Frequências com '{letra_chave}'")
            confirmar = input("Confirmar? (S): ").upper()
            if confirmar == "S":
                chave_descoberta[posicao] = letra_chave.upper()
                break

    print(f"\nCHAVE FINAL ({idioma.upper()}): {''.join(chave_descoberta)}")
    texto_decifrado = decifrar_vigenere(cifra, ''.join(chave_descoberta).lower())
    print("\n=== TEXTO DECIFRADO ===\n")
    print(texto_decifrado)


# === EXECUÇÃO AUTOMÁTICA EM SEQUÊNCIA: PT -> EN ===
processar_texto(plaintext_portugues, chave_pt, frequencia_portugues, 'pt')
processar_texto(plaintext_ingles, chave_en, frequencia_ingles, 'en')