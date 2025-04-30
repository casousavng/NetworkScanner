
🧠 NetworkScanner

NetworkScanner é uma aplicação de varrimento de rede local com interface gráfica embutida. Desenvolvida em Python, esta ferramenta permite descobrir dispositivos conectados à rede local, consultar informações detalhadas, visualizar o histórico de varrimentos e muito mais — tudo sem depender de um navegador externo.

🔧 Tecnologias Utilizadas
	•	Python 3.8+
	•	Flask para o backend web
	•	SQLite para persistência de dados
	•	Pywebview para interface gráfica com navegador embutido
	•	NMAP / Scapy / os / subprocess para varrimento de rede
	•	Jinja2 para templates
	•	Bootstrap / CSS para interface visual
	•	Threading para execução de varrimentos em segundo plano

⸻

🚀 Funcionalidades Principais
	•	🔍 Varrimento de dispositivos na rede local (nmap scans)
	•	📜 Armazenamento em base de dados local (rede.db)
	•	🕓 Histórico de varrimentos por data/hora
	•	👁️ Interface intuitiva aberta em navegador embutido (não depende de navegador externo)
	•	🧠 Detecção de fabricantes via endereço MAC
	•	🌐 Visualização de topologia da rede
	•	🧪 Sistema básico de testes

⸻

📦 Instalação e Execução

Pré-requisitos
	•	Python 3.8 ou superior
	•	pip
	•	Recomendado: ambiente virtual

1. Clonar o Repositório

git clone https://github.com/casousavng/NetworkScanner.git
cd NetworkScanner

2. Criar Ambiente Virtual (Opcional, Recomendado)

python -m venv venv
source venv/bin/activate  # No Windows: venv\Scripts\activate

3. Instalar Dependências

pip install -r requirements.txt

4. Inicializar a Base de Dados

python db_init.py

5. Executar a Aplicação com Interface Embutida

python start_app.py

Isto abrirá automaticamente uma janela com a interface gráfica do NetworkScanner.

⸻

🔐 Segurança e Privacidade
	•	Não envia nenhum dado para fora da máquina local.
	•	Ficheiros sensíveis como .env e rede.db são mantidos localmente e não são incluídos no controlo de versão.

⸻

🛠️ Desenvolvimento
	•	Adicionar novos métodos de varrimento: ver app/routes.py
	•	Modificar UI: editar templates/ e static/
	•	Scripts auxiliares: como db_init.py e schema.sql para estrutura da base de dados

⸻

🤝 Contribuir

Pull Requests são bem-vindos. Por favor, abre uma issue para discutir mudanças significativas antes de enviar.

⸻

📄 Licença

Distribuído sob licença MIT. Ver LICENSE para mais detalhes.

⸻

Se precisares de mais alguma informação ou ajuda adicional, estou à disposição!