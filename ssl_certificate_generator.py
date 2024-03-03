import socket
import uuid
from typing import List

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

    passphrase = passphrase.encode()

    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    serialnumber= int(uuid.uuid4())

    cert = crypto.X509()

    subject = cert.get_subject()
    subject.CN = common_name
    subject.O = organization_name
    subject.OU = organizational_unit_name

    cert.set_version(2)
    cert.set_issuer(subject)
    cert.set_serial_number(serialnumber)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(days * 24 * 60 * 60)
    cert.add_extensions([
        crypto.X509Extension(b'basicConstraints', True, b'CA:TRUE, pathlen:0'),
    ])
    cert.set_pubkey(key)
    cert.sign(key, 'sha512')

    with open('ca.key', 'wb') as fo:
        fo.write(crypto.dump_privatekey(
            crypto.FILETYPE_PEM, key, passphrase=passphrase
        ))

    with open('ca.crt', 'wb') as fo:
        fo.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))


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

    Webpack dev server:
        devServer: {
            server: {
                type: 'https',
                options: {
                    ca: fs.readFileSync('ca.crt'),
                    key: fs.readFileSync('cert.key'),
                    cert: fs.readFileSync('cert.crt'),
                    passphrase: ...your passphrase...,
                },
            }
        }

    Nginx:
        http {
            server {
                listen 443 ssl;

                ssl_certificate cert.crt;
                ssl_certificate_key cert.key;
            }
        }

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

    subject = cert_req.get_subject()
    subject.C = C
    subject.ST = ST
    subject.L = L
    subject.O = O
    subject.CN = CN
    subject.emailAddress = email_address

    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    cert = crypto.X509()
    cert.set_version(2)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(days * 24 * 60 * 60)
    cert.set_issuer(ca_cert.get_subject())
    cert.set_subject(subject)
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

    with open('cert.crt', 'wb') as fo:
        fo.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

    with open('cert.key', 'wb') as fo:
        fo.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

    # Generate importable cert for browser
    pkcs = crypto.PKCS12()
    pkcs.set_privatekey(key)
    pkcs.set_certificate(cert)
    with open('cert.p12', 'wb') as file:
        file.write(pkcs.export(passphrase=passphrase))


with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    s.connect(('8.8.8.8', 0))
    develop_ip = s.getsockname()[0]

passphrase = 'develop'

create_ca_certificate(passphrase)
create_domain_certificate(passphrase, domains=[
    develop_ip,
    '127.0.0.1',
    'develop.local'
])
