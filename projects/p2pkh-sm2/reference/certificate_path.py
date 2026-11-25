"""OpenSSL path validation against a caller-selected trust anchor."""

import os
from pathlib import Path
import re
from shutil import which
import subprocess
from tempfile import TemporaryDirectory
from time import monotonic

from asn1crypto.x509 import Name
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import InvalidVersion, load_der_x509_certificate


_OPENSSL_INSTALL_DIRECTORIES = ('/opt/homebrew/bin', '/usr/local/bin', '/usr/bin', '/bin')


def _openssl_executable(path):
    if path is None:
        path = which('openssl', path=os.pathsep.join(_OPENSSL_INSTALL_DIRECTORIES))
        if path is None:
            raise ValueError('OpenSSL not found in system install directories; supply openssl_path')
    try:
        executable = Path(path)
    except TypeError as error:
        raise ValueError('openssl_path must be an absolute executable path') from error
    if not executable.is_absolute():
        raise ValueError('openssl_path must be an absolute executable path')
    return executable


def _load_certificate(encoded, role):
    if not isinstance(encoded, bytes):
        raise ValueError(f'expected a DER {role} certificate')
    try:
        return load_der_x509_certificate(encoded)
    except InvalidVersion as error:
        # GB/T 20518 permits v2, but this loader and the revocation logic
        # built on it accept only v1 and v3. Fail closed with the API's type.
        raise ValueError(f'unsupported {role} certificate version: {error}') from error
    except ValueError as error:
        raise ValueError(f'invalid DER {role} certificate') from error


def _validity_error(certificate, when):
    if when < certificate.not_valid_before_utc:
        return 'certificate is not yet valid'
    if when > certificate.not_valid_after_utc:
        return 'certificate has expired'
    return None


def _require_validity(certificate, role, when):
    error = _validity_error(certificate, when)
    if error is not None:
        raise ValueError(f'{role} certificate path validation failed: {error}')


def _openssl(command, workspace, *, deadline):
    timeout = deadline - monotonic()
    if timeout <= 0:
        raise ValueError('OpenSSL certificate path validation timed out')
    try:
        env = {'LC_ALL': 'C', 'OPENSSL_CONF': os.devnull}
        return subprocess.run(command, cwd=workspace, env=env, capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError('OpenSSL certificate path validation could not run') from error


def _subject_key(certificate):
    # In -show_chain, request numeric OIDs and DER dumps for all values.
    # RDNs appear in reverse order, with unordered attributes inside each
    # RDN. DER hex keeps separators and untrusted text out of the labels.
    name = Name.load(certificate.subject.public_bytes(), strict=True)
    return tuple(
        tuple(sorted(f"{attribute['type'].dotted}=#{attribute['value'].dump().hex().upper()}".encode('ascii')
                     for attribute in rdn))
        for rdn in reversed(name.chosen)
    )


def _reported_subject(label):
    return tuple(tuple(sorted(rdn.split(b'+'))) for rdn in label.split(b',')) if label else ()


def _selected_path(stdout, candidate, trust_anchor, subjects, intermediate_subjects):
    marker = b' (untrusted)'
    rows = re.findall(rb'^depth=([0-9]+): (.*)$', stdout, re.MULTILINE)
    if (not rows or [int(depth) for depth, _ in rows] != list(range(len(rows)))
            or _reported_subject(rows[-1][1]) != subjects[trust_anchor]):
        raise ValueError('OpenSSL could not identify the selected certificate path to the trust anchor')
    if len(rows) == 1:
        if candidate != trust_anchor:
            raise ValueError('OpenSSL selected a different certificate as the target trust anchor')
        return (trust_anchor,)
    leaf = rows[0][1]
    if not leaf.endswith(marker) or _reported_subject(leaf.removesuffix(marker)) != subjects[candidate]:
        raise ValueError('OpenSSL could not identify the selected path target')
    chain = [candidate]
    for _, label in rows[1:-1]:
        if not label.endswith(marker):
            raise ValueError('OpenSSL could not identify a selected path intermediate')
        matches = intermediate_subjects.get(_reported_subject(label.removesuffix(marker)), ())
        if len(matches) != 1 or matches[0] in chain or matches[0] == trust_anchor:
            raise ValueError('selected certificate path has an ambiguous intermediate subject')
        chain.append(matches[0])
    return (*chain, trust_anchor)


def verify_revocation_paths(target, signers, *, trust_anchor, intermediates, validation_time,
                            identify=False, openssl_path=None):
    """Validate paths under one anchor and optionally return the selected DER chains."""
    deadline = monotonic() + 15
    anchor = _load_certificate(trust_anchor, 'trust anchor')
    _require_validity(anchor, 'trust anchor', validation_time)
    anchor_pem = anchor.public_bytes(Encoding.PEM)
    untrusted = {}
    subjects = {trust_anchor: _subject_key(anchor)} if identify else {}
    intermediate_subjects = {}
    for encoded in intermediates:
        if monotonic() >= deadline:
            raise ValueError('OpenSSL certificate path validation timed out')
        if isinstance(encoded, bytes) and encoded in untrusted:
            continue
        certificate = _load_certificate(encoded, 'intermediate')
        if _validity_error(certificate, validation_time) is None:
            untrusted[encoded] = certificate.public_bytes(Encoding.PEM)
            if identify:
                subject = _subject_key(certificate)
                subjects[encoded] = subject
                intermediate_subjects.setdefault(subject, []).append(encoded)
    untrusted_pem = b''.join(untrusted.values())
    with TemporaryDirectory(prefix='bsv-x509-revocation-path-') as directory:
        workspace = Path(directory)
        (workspace / 'anchor.pem').write_bytes(anchor_pem)
        # The default PKIX initial policy set is anyPolicy, including when
        # an intermediate requires an explicit policy later in the path.
        # Every supplied path candidate is time-checked here with inclusive
        # endpoints. OpenSSL's -attime would exclude the notAfter instant.
        command = [_openssl_executable(openssl_path), 'verify', '-no-CAfile', '-no-CApath', '-no-CAstore',
                   '-trusted', 'anchor.pem', '-partial_chain', '-x509_strict', '-policy_check',
                   '-policy', '2.5.29.32.0', '-no_check_time']
        if untrusted_pem:
            (workspace / 'intermediates.pem').write_bytes(untrusted_pem)
            command += ['-untrusted', 'intermediates.pem']
        certificates = [(target, 'target', 'any')]
        certificates += [(cert, 'CRL signer', 'crlsign') for cert in signers]
        if identify:
            command += ['-show_chain', '-nameopt', 'RFC2253,oid,dump_all,dump_der']
        selected = {}
        for encoded, role, purpose in certificates:
            certificate = _load_certificate(encoded, role)
            _require_validity(certificate, role, validation_time)
            pem = certificate.public_bytes(Encoding.PEM)
            (workspace / 'candidate.pem').write_bytes(pem)
            result = _openssl([*command, '-purpose', purpose, 'candidate.pem'], workspace, deadline=deadline)
            if result.returncode != 0:
                detail = ' '.join(result.stderr.decode(errors='replace').split())
                raise ValueError(f'{role} certificate path validation failed: {detail}')
            if identify:
                if encoded not in subjects:
                    subjects[encoded] = _subject_key(certificate)
                chain = _selected_path(result.stdout, encoded, trust_anchor, subjects, intermediate_subjects)
                if encoded in selected and selected[encoded] != chain:
                    raise ValueError('OpenSSL selected different target and CRL signer paths for the same certificate')
                selected[encoded] = chain
        return selected if identify else None
