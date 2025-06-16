
import google.generativeai as genai

# Cole sua chave de API aqui
GEMINI_API_KEY = "AIzaSyBMblnQRiKrXizWbirc_fQ4wPqpSX1FHcM"

# Configurar a API Gemini
genai.configure(api_key=GEMINI_API_KEY)
model = genai.GenerativeModel('gemini-2.0-flash-001')

def fazer_pergunta(pergunta):
    """Envia uma pergunta para o modelo Gemini e retorna a resposta."""
    try:
        response = model.generate_content(pergunta)
        return response.text
    except Exception as e:
        return f"Ocorreu um erro: {e}"

if __name__ == "__main__":
    print("Bem-vindo ao Gemini no CLI!")

    pergunta_base = "Todas as perguntas devem ser respondidas em português de portugal em apenas duas linhas. " \

    #pergunta_utilizado = "diz me em duas linhas o que é a inteligência artificial"
    pergunta_utilizado = "com base neste CVE-2023-50387 qual a meljor forma de mitigar este problema? https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-50387"
    print("Resposta do Gemini:\n")
    print("Pergunta: " + pergunta_base + pergunta_utilizado)
    resposta = fazer_pergunta(pergunta_base + pergunta_utilizado)
    print(resposta)
    
    
    #while True:
    #    pergunta_usuario = input("Digite sua pergunta (ou 'sair' para encerrar): ")
    #    if pergunta_usuario.lower() == 'sair':
    #        print("Encerrando...")
    #        break
    #    if pergunta_usuario:
    #        resposta = fazer_pergunta(pergunta_usuario)
    #        print("Resposta do Gemini:")
    #        print(resposta)
    #    else:
    #        print("Por favor, digite uma pergunta.")