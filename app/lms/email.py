import os

import smtplib as smtp
from dotenv import load_dotenv

load_dotenv()


def send_email(password_acc, email_personal, email_login):
    login = os.getenv('login')
    password = os.getenv('password')
    server = smtp.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(login, password)
    subject = 'Registration'
    text = (
        'Hello! Thank you for registering on our website! Here are your login credentials.\n'
        'Domain:\nhttps://lms.hrlearning.test\n'
        f'Login: {email_login}\n'
        f'Password: {password_acc}'
    )
    subject_utf8 = subject.encode('utf-8').decode('utf-8')
    text_utf8 = text.encode('utf-8').decode('utf-8')
    message = f'Subject:{subject_utf8}\n\n{text_utf8}'
    server.sendmail(login, email_personal, message.encode('utf-8'))
