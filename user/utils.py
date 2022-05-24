from django.contrib.auth.tokens import PasswordResetTokenGenerator
import six


class TokenGenerator(PasswordResetTokenGenerator):

    def __hash__(self, user, timestamp):
        return (six.text_type(user.id) + six.text_type(timestamp) + six.text_type(user.is_email_verified))


generate_token = TokenGenerator()