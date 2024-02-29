import re
from django.core.exceptions import ValidationError


phone_number_validator = re.compile(r'^\+[0-9]{1,16}$')


def validate_phone_number(value):
    if not phone_number_validator.match(value):
        raise ValidationError("Invalid phone number format.")
