# SPDX-License-Identifier: GPL-3.0-or-later
"""Lab certificate authority.

Malware over HTTPS expects a TLS handshake to succeed. Rather than ship a fixed
cert, we mint a throwaway CA on first run and generate leaf certs on demand.
The CA is lab-local and self-signed — it exists only so the handshake completes
and traffic can be observed. Never use these certs outside an isolated lab.
"""

from __future__ import annotations

import datetime
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


class LabCA:
    def __init__(self, ca_dir: str | Path) -> None:
        self.ca_dir = Path(ca_dir)
        self.ca_dir.mkdir(parents=True, exist_ok=True)
        self.ca_cert_path = self.ca_dir / "lyrebird-ca.crt"
        self.ca_key_path = self.ca_dir / "lyrebird-ca.key"
        self._key = None
        self._cert = None

    def ensure(self) -> None:
        if self.ca_cert_path.exists() and self.ca_key_path.exists():
            self._key = serialization.load_pem_private_key(
                self.ca_key_path.read_bytes(), password=None)
            self._cert = x509.load_pem_x509_certificate(self.ca_cert_path.read_bytes())
            return
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(_name("Lyrebird Lab CA"))
            .issuer_name(_name("Lyrebird Lab CA"))
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        )
        self.ca_key_path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()))
        self.ca_cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        self._key, self._cert = key, cert

    def leaf(self, hostname: str = "lab.local") -> tuple[Path, Path]:
        """Return (cert_path, key_path) for a leaf cert, minting if needed."""
        self.ensure()
        leaf_cert = self.ca_dir / f"{hostname}.crt"
        leaf_key = self.ca_dir / f"{hostname}.key"
        if leaf_cert.exists() and leaf_key.exists():
            return leaf_cert, leaf_key

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.datetime.now(datetime.timezone.utc)
        san: list[x509.GeneralName] = [x509.DNSName(hostname), x509.DNSName("*." + hostname)]
        try:
            san.append(x509.IPAddress(ipaddress.ip_address(hostname)))
        except ValueError:
            pass
        cert = (
            x509.CertificateBuilder()
            .subject_name(_name(hostname))
            .issuer_name(self._cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=825))
            .add_extension(x509.SubjectAlternativeName(san), critical=False)
            .sign(self._key, hashes.SHA256())
        )
        leaf_key.write_bytes(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()))
        leaf_cert.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        return leaf_cert, leaf_key