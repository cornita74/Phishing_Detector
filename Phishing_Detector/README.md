Phishing Detector
Ferramenta de linha de comando desenvolvida em Python para análise de URLs suspeitas. O detector aplica múltiplas heurísticas de segurança e integra a API do VirusTotal para calcular a probabilidade de uma URL ser maliciosa.

Funcionalidades

Verificação de protocolo HTTPS
Detecção de endereço IP no lugar de domínio
Identificação de URLs longas
Detecção de uso de @ para mascarar destino real
Análise de hífen e subdomínios excessivos no domínio
Identificação de palavras-chave suspeitas (login, verify, paypal, etc.)
Verificação da idade do domínio via WHOIS
Integração com a API do VirusTotal para consulta a múltiplos motores de detecção
Sistema de pontuação com resultado em porcentagem e classificação de risco


Exemplo de uso
bashpython detector.py
Entrada:
http://paypal-login-security.xyz
Saída:
Resultado da análise:

Probabilidade de phishing: 85%

*PROBLEMA!* ALTO RISCO DE PHISHING

Motivos:
- Sem HTTPS
- Palavras suspeitas
- Domínio recente
- 3 motores detectaram ameaca (VirusTotal)

Instalação
Clone o repositório:
bashgit clone https://github.com/SEU-USUARIO/phishing-detector.git
cd phishing-detector
Instale as dependências:
bashpip install -r requirements.txt

Configuracao da API (VirusTotal)
Crie um arquivo .env na raiz do projeto com o seguinte conteúdo:
VT_API_KEY=SUA_CHAVE_AQUI
Caso nenhuma chave seja fornecida, a ferramenta funciona normalmente sem a etapa de verificacao no VirusTotal.
Obtenha uma chave gratuita em: https://www.virustotal.com/

# Classificação de risco

| Pontuação | Classificação |
|-----------|---------------|
| 70 a 100  | Alto risco de phishing |
| 40 a 69   | Risco moderado |
| 0 a 39    | Provavelmente seguro |

Estrutura do projeto
phishing-detector/
├── detector.py
├── requirements.txt
├── README.md
├── exemplos.txt
├── .env.example
└── .gitignore

Dependencias
As dependencias estao listadas em requirements.txt:

# "pip install -r requirements.txt"

requests
python-whois
tldextract
python-dotenv

URLs de exemplo para teste
O arquivo exemplos.txt inclui URLs para testes rapidos:
https://google.com
http://paypal-login-security.xyz
http://192.168.1.1/login
http://paypal.com@malicious-site.xyz