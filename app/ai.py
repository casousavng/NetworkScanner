# -*- coding: utf-8 -*-

import markdown2
import google.generativeai as genai

# Configura a chave da API Gemini
genai.configure(api_key="AIzaSyBMblnQRiKrXizWbirc_fQ4wPqpSX1FHcM")

# Inicializa o modelo Gemini
model = genai.GenerativeModel('gemini-2.0-flash-001')

def fazer_pergunta(prompt, tem_cves=False, tem_edbs=False, tem_portas_abertas=False):
    if not any([tem_cves, tem_edbs, tem_portas_abertas]):
        return (
            "<p>Não foram detetadas portas abertas, serviços vulneráveis, CVEs ou EDBs neste dispositivo.</p>"
            "<p>Recomenda-se manter o dispositivo atualizado e monitorizar regularmente para garantir a segurança.</p>"
        )

    full_prompt = f"""
És um especialista em cibersegurança. Recebeste a saída de uma análise de segurança a um IP com possíveis vulnerabilidades.

A tua tarefa:
- Analisar serviços vulneráveis, versões desatualizadas, CVEs e referências EDB identificadas.
- Gerar um plano de mitigação bem estruturado.
- Responder de forma clara e técnica, com foco em segurança.
- Não deves usar linguagem de programação.
- Não deves usar tabelas, mas podes usar listas ordenadas ou não ordenadas.
- Usa títulos com ## para separar secções.
- Usa Markdown para formatar a resposta (negrito, listas, links, etc).

Formato esperado:

## 1. Resumo do risco
Breve descrição geral dos riscos identificados.

## 2. Análise e mitigação de CVEs
- Para cada CVE encontrado, explica o que representa e como mitigar.

## 3. Análise e mitigação de EDBs
- Para cada EDB identificado, descreve o tipo de exploração, impacto e forma de proteção.

## 4. Sugestões adicionais de segurança
Recomendações extra (ex: hardening, firewall, etc.).

## 5. Links de referência
- Fontes e documentação úteis.

--- Dados de entrada ---

{prompt}

Gera a resposta em português de Portugal, de forma clara, profissional e com linguagem técnica acessível.
    """

    response = model.generate_content(full_prompt)
    return markdown2.markdown(response.text.strip())