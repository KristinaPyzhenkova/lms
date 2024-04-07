import os
import re
import base64

import smtplib as smtp
from email.mime.text import MIMEText
import email
from email.header import decode_header
import imaplib
from dotenv import load_dotenv

from lms.helpers import log_info

from lms import models

load_dotenv()


def send_email_gmail(password_acc, email_personal, email_login):
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


def send_email_webmail(text_msg, topic, recipient, mailbox):
    server = smtp.SMTP_SSL('lmscreators.com', 465)
    # login_webmail = os.getenv('login_webmail')
    # password_webmail = os.getenv('password_webmail')
    login_webmail = mailbox.email
    password_webmail = os.getenv(mailbox.password)
    server.login(login_webmail, password_webmail)

    msg = MIMEMultipart()
    msg.attach(MIMEText(html_msg, 'html'))
    msg['Subject'] = topic
    msg['From'] = login_webmail
    msg['To'] = recipient

    server.sendmail(login_webmail, recipient, msg.as_string())
    server.quit()


def extract_sender_info_webmail(encoded_string):
    encoded_name, email_address = encoded_string.split(' <')
    encoded_name = encoded_name.strip()
    email_address = email_address.replace('>', '').strip()
    match = re.match(r'=\?.+\?B\?.+\?=', encoded_name)
    if match:
        encoded_name = encoded_name.replace('=?utf-8?B?', '').replace('?=', '')
        encoded_name = base64.b64decode(encoded_name).decode('utf-8')
    return encoded_name, email_address


def parsing_webmail(mailbox, last_num):
    login_webmail = mailbox.email
    password_webmail = os.getenv(mailbox.password)
    server = imaplib.IMAP4_SSL('lmscreators.com')
    server.login(login_webmail, password_webmail)
    server.select("inbox")
    result, data = server.search(None, "ALL")
    email_ids = data[0].split()
    filtered_ids = [num for num in email_ids if int(num) >= last_num]
    for num in filtered_ids:
        _, data = server.fetch(num, '(RFC822)')
        raw_email = data[0][1]
        email_message = email.message_from_bytes(raw_email)
        
        decoded_subject = decode_header(email_message['Subject'])
        subject = ''
        for part, encoding in decoded_subject:
            if isinstance(part, bytes):
                subject += part.decode(encoding or 'utf-8')
            else:
                subject += part
        
        decoded_name, email_address = extract_sender_info_webmail(email_message['From'])
        combined_text_body = ""
        combined_html_body = ""

        # Проверяем, есть ли мультипарт сообщение (если есть, значит, есть как текстовая, так и HTML-версии)
        if email_message.is_multipart():
            for part in email_message.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))

                # Ищем текстовое тело письма и добавляем его к общему текстовому телу
                if content_type == "text/plain" and "attachment" not in content_disposition:
                    text_body = part.get_payload(decode=True)
                    if text_body:
                        combined_text_body += text_body.decode(part.get_content_charset() or 'utf-8', 'ignore')

                # Ищем HTML-тело письма и добавляем его к общему HTML-телу
                elif content_type == "text/html" and "attachment" not in content_disposition:
                    html_body = part.get_payload(decode=True)
                    if html_body:
                        combined_html_body += html_body.decode(part.get_content_charset() or 'utf-8', 'ignore')

        # Если нет мультипарт сообщения, возможно, у нас есть просто текстовое письмо
        else:
            content_type = email_message.get_content_type()
            if content_type == "text/plain":
                text_body = email_message.get_payload(decode=True)
                if text_body:
                    combined_text_body += text_body.decode(email_message.get_content_charset() or 'utf-8', 'ignore')
            elif content_type == "text/html":
                html_body = email_message.get_payload(decode=True)
                if html_body:
                    combined_html_body += html_body.decode(email_message.get_content_charset() or 'utf-8', 'ignore')

        combined_content = combined_html_body if combined_html_body else combined_text_body
        email_obj, created = models.EmailSMTP.objects.get_or_create(
            sender=email_address,
            recipient=login_webmail,
            subject=subject,
            body=combined_content,
            mailbox=mailbox,
            id_inbox=int(num)
        )
    server.logout()
    



# Подключение к IMAP серверу

# parsing_email(mail, '3')
# Завершение соединения

