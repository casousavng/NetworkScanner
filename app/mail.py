from flask_mail import Mail, Message

mail = Mail()

def init_mail(app):
    mail.init_app(app)

def send_issue_report(issue_text, recipient_email):
    msg = Message(subject="Novo problema reportado - NetworkScanner",
                  sender="from@example.com",  # pode ser algo fixo ou do .env
                  recipients=[recipient_email])
    msg.body = f"Problema reportado - NetworkScanner:\n\n{issue_text}"
    mail.send(msg)