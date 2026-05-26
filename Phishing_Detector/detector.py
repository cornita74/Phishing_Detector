import re
import whois
import tldextract
import requests
import os
from dotenv import load_dotenv
from datetime import datetime

# carregar variáveis do .env
load_dotenv()
API_KEY = os.getenv("VirusTotal_API_KEY")


# =======================================================================

def verificar_https(url):
    return not url.startswith("https://")


def verificar_ip(url):
    return bool(re.match(r"https?://\d+\.\d+\.\d+\.\d+", url))


def verificar_url_longa(url):
    return len(url) > 75


def verificar_arroba(url):
    return "@" in url


def verificar_hifen(url):
    dominio = tldextract.extract(url).domain
    return "-" in dominio


def verificar_subdominio(url):
    sub = tldextract.extract(url).subdomain
    return sub.count(".") >= 1


def verificar_palavras_suspeitas(url):
    palavras = [
        "login", "verify", "update", "secure",
        "account", "bank", "paypal", "confirm",
        "password", "signin"
    ]
    return any(p in url.lower() for p in palavras)


def verificar_idade_dominio(url):
    dominio = tldextract.extract(url).domain + "." + tldextract.extract(url).suffix

    try:
        info = whois.whois(dominio)
        data = info.creation_date

        if isinstance(data, list):
            data = data[0]

        idade = (datetime.now() - data).days
        return idade < 180

    except:
        return False


def verificar_virustotal(url):

    if not API_KEY:
        return 0

    headers = {"x-apikey": API_KEY}

    try:
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url}
        )

        if response.status_code != 200:
            return 0

        url_id = response.json()["data"]["id"]

        report = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{url_id}",
            headers=headers
        )

        if report.status_code != 200:
            return 0

        stats = report.json()["data"]["attributes"]["stats"]

        return stats["malicious"] + stats["suspicious"]

    except:
        return 0


# ==========================================================================

def analisar(url):

    score = 0
    motivos = []

    if verificar_https(url):
        score += 10
        motivos.append("Sem HTTPS")

    if verificar_ip(url):
        score += 20
        motivos.append("Uso de IP")

    if verificar_url_longa(url):
        score += 10
        motivos.append("URL muito longa")

    # 🔥 MELHORADO AQUI
    if verificar_arroba(url):
        score += 30
        motivos.append("Uso de @ (técnica comum de phishing)")

        # detectar tentativa de enganar
        parte_antes = url.split("@")[0]
        if "http" in parte_antes:
            score += 10
            motivos.append("Tentativa de mascarar URL antes do @")

    if verificar_hifen(url):
        score += 10
        motivos.append("Hífen no domínio")

    if verificar_subdominio(url):
        score += 10
        motivos.append("Muitos subdomínios")

    if verificar_palavras_suspeitas(url):
        score += 15
        motivos.append("Palavras suspeitas")

    if verificar_idade_dominio(url):
        score += 20
        motivos.append("Domínio recente")

    vt = verificar_virustotal(url)
    if vt > 0:
        score += 40
        motivos.append(f"{vt} motores detectaram ameaça (VirusTotal)")

    # limite máximo
    if score > 100:
        score = 100

# ============================================================================

    print("\n Resultado da análise:\n")
    print(f"Probabilidade de phishing: {score}%\n")

    if score >= 70:
        print("*PROBLEMA!* ALTO RISCO DE PHISHING")
    elif score >= 40:
        print("*ALERTA!* RISCO MODERADO")
    else:
        print("*Relaxa!* PROVAVELMENTE SEGURO")

    print("\nMotivos:")

    if not motivos:
        print("Nenhum comportamento suspeito")

    for m in motivos:
        print("-", m)

# ==========================================================================

if __name__ == "__main__":
    url = input("Digite a URL para análise: ")
    analisar(url)