import binascii
import string

from django import forms
from django.db import models
from django.conf import settings
from django.utils.encoding import smart_str


USE_CPICKLE = getattr(settings, 'USE_CPICKLE', False)

if USE_CPICKLE:
    import cPickle as pickle
else:
    import pickle

class BaseEncryptedField(models.Field):
    '''This code is based on the djangosnippet #1095
       You can find the original at http://www.djangosnippets.org/snippets/1095/'''

    def __init__(self, *args, **kwargs):
        cipher = kwargs.pop('cipher', 'AES')
        try:
            imp = __import__('Crypto.Cipher', globals(), locals(), [cipher], -1)
        except:
            imp = __import__('Crypto.Cipher', globals(), locals(), [cipher])
        self.cipher = getattr(imp, cipher).new(settings.SECRET_KEY[:32])
        self.prefix = '$%s$' % cipher

        # For the worst case scenario we support up to 3 bytes per unicode character
        max_length = kwargs.get('max_length', 40) * 3
        mod = max_length % self.cipher.block_size
        # http://www.obviex.com/Articles/CiphertextSize.aspx
        if mod > 0:
            max_length += self.cipher.block_size - mod

        # This formula is made and tested for max 3 bytes unicode strings
        # (the ones that MySQL supports) b2a_base64 and cipher.block_size=16
        kwargs['max_length'] = (max_length / self.cipher.block_size) * (self.cipher.block_size / 4 * 5) + \
            (max_length + self.cipher.block_size * 3 - 1) / (self.cipher.block_size * 3) * 4 \
            + len(self.prefix) + 1
        models.Field.__init__(self, *args, **kwargs)

    def _is_encrypted(self, value):
        return isinstance(value, basestring) and value.startswith(self.prefix)

    def _get_padding(self, value):
        mod = len(value) % self.cipher.block_size
        if mod > 0:
            return self.cipher.block_size - mod
        return 0


    def to_python(self, value):
        if self._is_encrypted(value):
            return unicode(self.cipher.decrypt(binascii.a2b_base64(
                value[len(self.prefix):])).split('\0')[0], 'utf-8')
        return value

    def get_db_prep_value(self, value):
        if value is not None and not self._is_encrypted(value):
            padding = self._get_padding(value.encode('utf-8'))
            if padding > 0:
                value += "\0" + ''.join(['X' for index in range(padding-1)])
            value = self.prefix + binascii.b2a_base64(self.cipher.encrypt( \
                value.encode('utf-8')))
        return value

class EncryptedTextField(BaseEncryptedField):
    __metaclass__ = models.SubfieldBase

    def get_internal_type(self):
        return 'TextField'

    def formfield(self, **kwargs):
        defaults = {'widget': forms.Textarea}
        defaults.update(kwargs)
        return super(EncryptedTextField, self).formfield(**defaults)

class EncryptedCharField(BaseEncryptedField):
    __metaclass__ = models.SubfieldBase

    def get_internal_type(self):
        return "CharField"

    def formfield(self, **kwargs):
        defaults = {'max_length': self.max_length}
        defaults.update(kwargs)
        return super(EncryptedCharField, self).formfield(**defaults)

class PickleField(models.TextField):
    __metaclass__ = models.SubfieldBase

    editable = False
    serialize = False

    def get_db_prep_value(self, value):
        return pickle.dumps(value)

    def to_python(self, value):
        if not isinstance(value, basestring):
            return value

        # Tries to convert unicode objects to string, cause loads pickle from
        # unicode excepts ugly ``KeyError: '\x00'``.
        try:
            return pickle.loads(smart_str(value))
        # If pickle could not loads from string it's means that it's Python
        # string saved to PickleField.
        except ValueError:
            return value
