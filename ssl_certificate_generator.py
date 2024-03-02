import datetime
import socket
import uuid
from typing import List

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from OpenSSL import crypto


def create_ca_certificate(
    passphrase: str,
    common_name='Develop CA',
    organization_name='Develop LLC',
    organizational_unit_name='Default CA Deployment',
    days=365,
):
    """Generate CA certificate

    Chrome manual:
        chrome://settings/certificates
        Authorities -> import -> ca.crt
        ☑ Trust this certificate for identifying websites
        ☑ Trust this certificate for identifying email users
        ☑ Trust this certificate for identifying software makers
        [ OK ]
    """

    one_day = datetime.timedelta(1, 0, 0)
    today = datetime.datetime.today()
    backend = default_backend()

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=backend
    )

    public_key = private_key.public_key()

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit_name),
    ]))
    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ]))
    builder = builder.not_valid_before(today - one_day)
    builder = builder.not_valid_after(today + datetime.timedelta(days=days))
    builder = builder.serial_number(int(uuid.uuid4()))
    builder = builder.public_key(public_key)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    )

    certificate = builder.sign(
        private_key=private_key, algorithm=hashes.SHA256(),
        backend=backend
    )

    with open('ca.key', 'wb') as fo:
        fo.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode())
        ))

    with open('ca.crt', 'wb') as fo:
        fo.write(certificate.public_bytes(
            encoding=serialization.Encoding.PEM,
        ))


def _domain_to_record(domain: str):
    try:
        socket.inet_aton(domain)
    except socket.error:
        return f'DNS:{domain}'
    else:
        return f'IP:{domain}'


def create_domain_certificate(
    passphrase: str,
    domains: List[str],
    days=365,
    C='RU', ST='Moscow', L='Moscow',
    O='Develop LLC', CN='Develop cert',
    email_address='developer@develop.local',
):
    """Generate website certificate

    Chrome manual:
        chrome://settings/certificates
        Your certificates -> import -> cert.p12
        [ enter your passphrase ]
        [ OK ]
    """

    passphrase = passphrase.encode()

    with open('ca.crt', 'rb') as fo:
        ca_cert = crypto.load_certificate(
            crypto.FILETYPE_PEM, fo.read())

    with open('ca.key', 'rb') as fo:
        ca_key = crypto.load_privatekey(
            crypto.FILETYPE_PEM, fo.read(),
            passphrase=passphrase)

    cert_req = crypto.X509Req()
    cert_req.get_subject().C = C
    cert_req.get_subject().ST = ST
    cert_req.get_subject().L = L
    cert_req.get_subject().O = O
    cert_req.get_subject().CN = CN
    cert_req.get_subject().emailAddress = email_address

    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    cert = crypto.X509()
    cert.set_version(2)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(days * 24 * 60 * 60)
    cert.set_issuer(ca_cert.get_subject())
    cert.set_subject(cert_req.get_subject())
    cert.add_extensions([
        crypto.X509Extension(
            b'subjectAltName', False,
            ','.join([
                _domain_to_record(domain)
                for domain in domains
            ]).encode()
        ),
    ])
    cert.set_pubkey(key)
    cert.sign(ca_key, 'sha256')

    with open('cert.crt', 'wb') as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

    with open('cert.key', 'wb') as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

    # Generate importable cert for browser
    pkcs = crypto.PKCS12()
    pkcs.set_privatekey(key)
    pkcs.set_certificate(cert)
    with open('cert.p12', 'wb') as file:
        file.write(pkcs.export(passphrase=passphrase))


create_ca_certificate('develop')
create_domain_certificate('develop', [
    '192.168.50.7',
    'develop.local'
])
