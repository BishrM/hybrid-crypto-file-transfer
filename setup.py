"""Packaging for CipherLink. Run-from-source (see README) is the supported way to use it;
this file exists so the dependency list is declared in one place for pip tooling.

Originally a packaging stub for the RSA/AES file-transfer CLI by Brian HVB
(project1_* directories, kept as the legacy prototype).
"""
from pathlib import Path

from setuptools import setup

requirements = [
    line.strip()
    for line in Path(__file__).with_name("requirements.txt").read_text().splitlines()
    if line.strip() and not line.startswith("#")
]

setup(
    name="cipherlink",
    version="1.0.0",
    description="Authenticated, encrypted peer-to-peer LAN file transfer (TLS 1.3, RSA-OAEP, AES-256-GCM)",
    url="https://github.com/soundaryakl/hybrid-crypto-file-transfer",
    author="CipherLink contributors; Brian HVB (original CLI prototype)",
    license="MIT",
    python_requires=">=3.11",
    py_modules=["main", "config", "crypto_engine", "network_p2p", "peer_store", "transfer_history", "gui_app"],
    install_requires=requirements,
    entry_points={"gui_scripts": ["cipherlink=main:main"]},
    zip_safe=False,
)
