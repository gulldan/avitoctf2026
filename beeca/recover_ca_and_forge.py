#!/usr/bin/env python3
"""Recover the BeeCA CA modulus from two signed leaves, factor it, forge CN=admin.

Usage: uv run python beeca/recover_ca_and_forge.py leaf.crt leaf2.crt
"""

import hashlib
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from gmpy2 import gcd as ggcd  # ty: ignore[unresolved-import]
from gmpy2 import isqrt as gisqrt  # ty: ignore[unresolved-import]
from gmpy2 import mpz  # ty: ignore[unresolved-import]

E = 65537
SHA256_DI_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")
OUTPUT_DIR = Path(__file__).resolve().parent


def load_leaf(path):
    cert = x509.load_pem_x509_certificate(open(path, "rb").read())
    tbs = cert.tbs_certificate_bytes
    sig = int.from_bytes(cert.signature, "big")
    public_key = cert.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError("expected an RSA leaf certificate")
    n_leaf = public_key.public_numbers().n
    return tbs, sig, n_leaf


def emsa(tbs, emlen):
    h = hashlib.sha256(tbs).digest()
    di = SHA256_DI_PREFIX + h
    ps = b"\xff" * (emlen - len(di) - 3)
    return int.from_bytes(b"\x00\x01" + ps + b"\x00" + di, "big")


def recover_N(leaves):
    # try candidate CA modulus byte-lengths; correct one makes s^e-EM a multiple of N
    for emlen in (256, 384, 512, 128, 256 + 0):
        Xs = []
        for tbs, s, _ in leaves:
            Xs.append(mpz(pow(mpz(s), E)) - emsa(tbs, emlen))
        g = Xs[0]
        for x in Xs[1:]:
            g = ggcd(g, x)
        # strip tiny cofactors
        g = int(g)
        for sf in range(2, 200000):
            while g % sf == 0 and (g // sf).bit_length() > 1500:
                g //= sf
        if g.bit_length() >= 1500:
            print(f"[+] recovered CA modulus N: {g.bit_length()} bits (emlen guess {emlen})")
            return g
    raise SystemExit(
        "[-] could not recover N (need >=2 DISTINCT leaves, or CA modulus size not in candidate list)"
    )


def fermat(n, maxi=1 << 26):
    a = int(gisqrt(mpz(n))) + 1
    for _ in range(maxi):
        b2 = a * a - n
        b = int(gisqrt(mpz(b2)))
        if b * b == b2:
            return a - b, a + b
        a += 1
    return None


def lehman(n, k_max=2000, iters_per_k=2000):
    """Fermat's method generalized with a multiplier k: catches p,q with p/q close to
    a small rational a/b (k = a*b) even when plain Fermat (k=1) finds nothing.
    """
    for k in range(2, k_max + 1):
        kn = mpz(k) * n
        a = gisqrt(kn)
        if a * a < kn:
            a += 1
        for _ in range(iters_per_k):
            b2 = a * a - kn
            if b2 >= 0:
                b = gisqrt(b2)
                if b * b == b2:
                    g = int(ggcd(a - b, mpz(n)))
                    if 1 < g < n:
                        print(f"[+] Lehman (multiplier k={k}) worked")
                        return g, n // g
            a += 1
    return None


def battery(N, leaf_moduli):
    # 1) small factors
    for sp in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]:
        if N % sp == 0:
            return sp, N // sp
    # 2) Fermat / close primes  (most likely for a hand-rolled "vibecoder" CA)
    f = fermat(N)
    if f:
        print("[+] Fermat (close primes) worked")
        return f
    # 3) shared prime with any leaf (batch-GCD)
    for m in leaf_moduli:
        g = int(ggcd(mpz(N), mpz(m)))
        if 1 < g < N:
            print("[+] shared prime with a leaf modulus (batch-GCD)")
            return g, N // g
    # 4) Lehman (generalized Fermat): the BeeCA CA key needed this -- plain Fermat
    # (k=1) finds nothing because p/q isn't literally close to 1, but it IS close
    # to a small rational a/b (k=a*b=99 here), which a multiplier search catches.
    lf = lehman(N)
    if lf:
        return lf
    # (extend with ROCA / Pollard-rho / known-prime DBs as needed)
    return None


def build_ca_key(N, p, q):
    q = N // p if N % p == 0 else q
    if p * q != N:
        p, q = q, p
    assert p * q == N
    d = pow(E, -1, (p - 1) * (q - 1))
    return rsa.RSAPrivateNumbers(
        p=p,
        q=q,
        d=d,
        dmp1=d % (p - 1),
        dmq1=d % (q - 1),
        iqmp=pow(q, -1, p),
        public_numbers=rsa.RSAPublicNumbers(E, N),
    ).private_key()


def forge_admin(ca_key):
    import datetime

    leaf_key = rsa.generate_private_key(public_exponent=E, key_size=2048)
    issuer = x509.Name(
        [  # must match trusted CA subject exactly: CN=BeeCA, O=BeeCA
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "BeeCA"),
            x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, "BeeCA"),
        ]
    )
    subject = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "admin")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(leaf_key.public_key())
        .serial_number(0x2000)  # отличается от leaf-серийников 0x1000/0x1001
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=29))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    cert_path = OUTPUT_DIR / "admin_forged.crt"
    key_path = OUTPUT_DIR / "admin_forged.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    print(f"[+] wrote {cert_path} / {key_path}  (CN=admin, signed by recovered CA)")
    print(f"    curl --cert {cert_path} --key {key_path} https://admin-bv5kavo6.beeca.avitoctf.ru/")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    leaves = [load_leaf(p) for p in sys.argv[1:]]
    leaf_moduli = [l[2] for l in leaves]
    N = recover_N(leaves)
    fac = battery(N, leaf_moduli)
    if not fac:
        print("[-] CA modulus not weak to the current battery. Extend with ROCA/rho/known-primes.")
        sys.exit(2)
    p, q = fac
    print(f"[+] factored CA: p={hex(p)[:24]}... q={hex(q)[:24]}...")
    forge_admin(build_ca_key(N, p, q))
