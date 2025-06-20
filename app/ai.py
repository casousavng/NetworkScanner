
# -*- coding: utf-8 -*-

import re
import google.generativeai as genai

# Configura a chave da API Gemini
genai.configure(api_key="AIzaSyBMblnQRiKrXizWbirc_fQ4wPqpSX1FHcM")

# Inicializa o modelo Gemini (podes escolher outro se quiseres)
model = genai.GenerativeModel('gemini-2.0-flash-001')

def fazer_pergunta(prompt, tem_cves=False, tem_edbs=False, tem_portas_abertas=False):
    if not any([tem_cves, tem_edbs, tem_portas_abertas]):
        return (
            "Não foram detetadas portas abertas, serviços vulneráveis, CVEs ou EDBs neste dispositivo.<br>"
            "Recomenda-se manter o dispositivo atualizado e monitorizar regularmente para garantir a segurança."
        )

    full_prompt = f"""
És um especialista em cibersegurança. Recebeste a saída de uma análise de segurança a um IP com possíveis vulnerabilidades.

A tua tarefa:
- Analisar serviços vulneráveis, versões desatualizadas, CVEs e referências EDB identificadas.
- Gerar um plano de mitigação bem estruturado.

Segue este formato de resposta:

1. Resumo do risco: breve descrição geral dos riscos identificados.
2. Análise e mitigação de CVEs:
   - Para cada CVE encontrado, explica o que representa e como mitigar.
3. Análise e mitigação de EDBs:
   - Para cada EDB identificado, descreve o tipo de exploração, impacto e forma de proteção.
4. Sugestões adicionais de segurança: recomendações extra (ex: hardening, firewall, etc.).
5. Links de referência: fontes e documentação úteis.

--- Dados de entrada ---

{prompt}

Gera a resposta em português de Portugal, de forma clara, profissional e com linguagem técnica acessível.
    """

    response = model.generate_content(full_prompt)
    return response.text.strip()


def formatar_resposta_markdown_para_html(texto):
    # Negrito
    texto = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', texto)
    # Itálico
    texto = re.sub(r'\*(.*?)\*', r'<em>\1</em>', texto)

    # Números/cardinais no início da linha -> lista ordenada
    texto = re.sub(r'(?m)^(\d+)\.\s+(.*)', r'<li>\2</li>', texto)
    texto = re.sub(r'(<li>.*?</li>)', r'<ol>\1</ol>', texto, count=0)

    # Asteriscos como bullet points -> lista não ordenada
    texto = re.sub(r'(?m)^\*\s+(.*)', r'<li>\1</li>', texto)
    texto = re.sub(r'(<li>.*?</li>)', r'<ul>\1</ul>', texto, count=0)

    # Quebra de linha normal
    texto = texto.replace('\n', '<br>')

    return texto

