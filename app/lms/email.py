import os
import re
import json
import base64

import smtplib as smtp
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
from email.utils import parseaddr
from email.mime.application import MIMEApplication
from email.mime.base import MIMEBase
from email import encoders
import email
from email.header import decode_header
import imaplib
from dotenv import load_dotenv
from django.conf import settings
from django.utils import timezone

from lms.helpers import log_info

from lms import models

load_dotenv()


def send_email_gmail(password_acc, email_personal, email_login):
    try:
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
    except Exception as e:
        log_info(f'{e = }')
        raise Exception(e)


def get_message_id(email_message):
    """Извлекает идентификатор сообщения из объекта email.message.EmailMessage"""
    message_id, encoding = decode_header(email_message['Message-ID'])[0]
    if encoding:
        message_id = message_id.decode(encoding)
    return message_id


def get_previous_email(mailbox, email_id):
    """Получает объект email.message.EmailMessage для предыдущего письма"""
    try:
        # Подключаемся к почтовому ящику
        mail = imaplib.IMAP4_SSL(mailbox.smtp_server)
        mail.login(mailbox.email, mailbox.password)

        # Выбираем папку входящих сообщений
        mail.select("inbox")

        # Получаем текст письма по его идентификатору
        _, data = mail.fetch(email_id, "(RFC822)")
        raw_email = data[0][1]

        # Создаем объект email.message.EmailMessage
        previous_email = email.message_from_bytes(raw_email)

        mail.logout()
        return previous_email
    except Exception as e:
        log_info(f"Ошибка при получении предыдущего письма: {e}")
        return None


def send_email_webmail(html_msg, topic, recipients, mailbox, attachments=None, in_reply_to=None):
    try:
        server = smtp.SMTP_SSL(mailbox.smtp_server, 465)
        login_webmail = mailbox.email
        password_webmail = mailbox.password
        server.login(login_webmail, password_webmail)

        msg = MIMEMultipart()
        msg.attach(MIMEText(html_msg, 'html'))
        msg['Subject'] = topic if not in_reply_to else ' Re: ' + topic
        msg['From'] = login_webmail
        msg['To'] = recipients
        log_info(f'{in_reply_to = }')
        if in_reply_to:
            previous_email = get_previous_email(mailbox, in_reply_to)
            in_reply = get_message_id(previous_email)
            log_info(f'{in_reply = }')
            msg['References'] = in_reply
            msg['In-Reply-To'] = in_reply

        if attachments:
            log_info(f'{attachments = }')
            for file_path in attachments:
                log_info(f'{file_path = }')
                with open(file_path, 'rb') as f:
                    part = None
                    if file_path.lower().endswith('.pdf'):
                        part = MIMEApplication(f.read(), Name=os.path.basename(file_path))
                    elif file_path.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
                        part = MIMEImage(f.read(), Name=os.path.basename(file_path))
                    else:
                        part = MIMEApplication(f.read(), Name=os.path.basename(file_path))
                part['Content-Disposition'] = f'attachment; filename="{os.path.basename(file_path)}"'
                msg.attach(part)

        server.sendmail(login_webmail, recipients, msg.as_string())
        server.quit()
    except Exception as e:
        log_info(f'{e = }')
        raise Exception(e)


# def extract_sender_info_webmail(encoded_string):
#     try:
#         encoded_name, email_address = encoded_string.split(' <')
#         encoded_name = encoded_name.strip()
#         email_address = email_address.replace('>', '').strip()
#         match = re.match(r'=\?.+\?B\?.+\?=', encoded_name)
#         if match:
#             encoded_name = encoded_name.replace('=?utf-8?B?', '').replace('?=', '')
#             encoded_name = base64.b64decode(encoded_name).decode('utf-8')
#         return encoded_name, email_address
#     except Exception as e:
#         log_info(f'{e = }')
#         raise Exception(e)
def extract_sender_info_webmail(encoded_string):
    try:
        # Используем parseaddr для извлечения имени и email
        name, email_address = parseaddr(encoded_string)
        
        # Декодируем имя, если оно закодировано
        decoded_name_parts = decode_header(name)
        decoded_name = ''
        for part, encoding in decoded_name_parts:
            if isinstance(part, bytes):
                decoded_name += part.decode(encoding or 'utf-8', 'ignore')
            else:
                decoded_name += part

        return decoded_name.strip(), email_address.strip()
    except Exception as e:
        log_info(f'{e = }')
        raise Exception(e)


def parsing_webmail(mailbox, last_num):
    try:
        login_webmail = mailbox.email
        password_webmail = mailbox.password
        server = imaplib.IMAP4_SSL(mailbox.smtp_server)
        server.login(login_webmail, password_webmail)
        server.select("inbox")
        result, data = server.search(None, "ALL")
        email_ids = data[0].split()
        data_files = []
        filtered_ids = [num for num in email_ids if int(num) > last_num]
        for num in filtered_ids:
            _, data = server.fetch(num, '(RFC822)')
            raw_email = data[0][1]
            email_message = email.message_from_bytes(raw_email)
            
            decoded_subject = decode_header(email_message['Subject'])
            subject = ''
            for part, encoding in decoded_subject:
                if isinstance(part, bytes):
                    try:
                        subject += part.decode(encoding or 'utf-8', 'ignore')
                    except Exception as e:
                        log_info(f'Subject decode error: {e}')
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
                    
                    elif "attachment" in content_disposition:
                        filename = part.get_filename()
                        if filename:
                            decoded_filename = decode_header(filename)
                            filename = ''
                            for part_, encoding in decoded_filename:
                                if isinstance(part_, bytes):
                                    filename += part_.decode(encoding or 'utf-8', 'ignore')
                                else:
                                    filename += part_
                        filepath = os.path.join(settings.MEDIA_ROOT, 'files', f'{timezone.now().date()}_{filename}')
                        with open(filepath, 'wb') as f:
                            f.write(part.get_payload(decode=True))
                        data_files.append(filepath)

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
                id_inbox=int(num),
                attachments=json.dumps(data_files)
            )
        server.logout()
    except Exception as e:
        log_info(f'{e = }')
        raise Exception(e)