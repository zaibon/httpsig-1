"""
Module to assist in verifying a signed header.
"""
import base64
import six

from .sign import Signer
from .utils import *
from nacl.signing import VerifyKey
from nacl.encoding import Base64Encoder
from nacl.exceptions import BadSignatureError 

class Verifier(Signer):
    """
    Verifies signed text against a secret.
    For HMAC, the secret is the shared secret.
    For RSA, the secret is the PUBLIC key.
    """

    def __init__(self,secret, algorithm=None):
        super(Verifier, self).__init__(secret=secret, algorithm=algorithm)
        # special case for ed25519 algo that needs to to use another type
        # for the key then the Signer class
        if self._ed25519:
            self._ed25519 = VerifyKey(secret, encoder=Base64Encoder)

    def _verify(self, data, signature):
        """
        Verifies the data matches a signed version with the given signature.
        `data` is the message to verify
        `signature` is a base64-encoded signature to verify against `data`
        """

        if isinstance(data, six.string_types):
            data = data.encode("ascii")
        if isinstance(signature, six.string_types):
            signature = signature.encode("ascii")

        if self.sign_algorithm == 'rsa':
            h = self._hash.new()
            h.update(data)
            return self._rsa.verify(h, base64.b64decode(signature))

        elif self.sign_algorithm == 'hmac':
            h = self._sign_hmac(data)
            s = base64.b64decode(signature)
            return ct_bytes_compare(h, s)

        elif self.sign_algorithm == 'ed25519':
            try:
                self._ed25519.verify(data, base64.b64decode(signature))
                return True
            except BadSignatureError:
                return False
        else:
            raise HttpSigException("Unsupported algorithm.")


class HeaderVerifier(Verifier):
    """
    Verifies an HTTP signature from given headers.
    """

    def __init__(self, headers, secret, required_headers=None, method=None,
                 path=None, host=None, sign_header='authorization'):
        """
        Instantiate a HeaderVerifier object.

        :param headers:             A dictionary of headers from the HTTP
            request.
        :param secret:              The HMAC secret or RSA *public* key.
        :param required_headers:    Optional. A list of headers required to
            be present to validate, even if the signature is otherwise valid.
            Defaults to ['date'].
        :param method:              Optional. The HTTP method used in the
            request (eg. "GET"). Required for the '(request-target)' header.
        :param path:                Optional. The HTTP path requested,
            exactly as sent (including query arguments and fragments).
            Required for the '(request-target)' header.
        :param host:                Optional. The value to use for the Host
            header, if not supplied in :param:headers.
        :param sign_header:         Optional. The header where the signature is.
            Default is 'authorization'.
        """
        required_headers = required_headers or ['date']
        self.headers = CaseInsensitiveDict(headers)

        if sign_header.lower() == 'authorization':
            auth = parse_authorization_header(self.headers['authorization'])
            if len(auth) == 2:
                self.auth_dict = auth[1]
            else:
                raise HttpSigException("Invalid authorization header.")
        else:
            self.auth_dict = parse_signature_header(self.headers[sign_header])

        self.required_headers = [s.lower() for s in required_headers]
        self.method = method
        self.path = path
        self.host = host

        super(HeaderVerifier, self).__init__(
                secret, algorithm=self.auth_dict['algorithm'])

    def verify(self):
        """
        Verify the headers based on the arguments passed at creation and
            current properties.

        Raises an Exception if a required header (:param:required_headers) is
            not found in the signature.
        Returns True or False.
        """
        auth_headers = self.auth_dict.get('headers', 'date').split(' ')

        if len(set(self.required_headers) - set(auth_headers)) > 0:
            error_headers = ', '.join(
                    set(self.required_headers) - set(auth_headers))
            raise Exception(
                    '{} is a required header(s)'.format(error_headers))

        signing_str = generate_message(
                auth_headers, self.headers, self.host, self.method, self.path)

        return self._verify(signing_str, self.auth_dict['signature'])
