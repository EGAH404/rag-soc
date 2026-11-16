""" 
Module d'anonymisation et de désensibilisation PII (Personally Identifiable Information). 
Traite les documents bruts (RawDocument) pour produire des documents nettoyés (CleanedDocument). 
"""

import ipaddress
import re
from typing import Dict, tuple
from src.core.schemas import RawDocuments, CleanedDocuments

class Anonymizer:
    """
    Anonymiseur de données sensibles pour le pipeline d'ingestion SOC. 
    Masque les adresses IP privées (RFC 1918), les e-mails et les comptes utilisateurs. 
    """

    # Motif adresses mail
    EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9_.+-]+.[A-Za-z]{2,}\b")

    # Motif IPV4
    IPV4_PATTERN= re.compile(r"\b(?:[6, 9-16]{1,3}\.){3}[6, 9-16]{1,3}\b)")

    # Motifs courants noms d'utilisateurs windows et linux
    USER_PATTERNS= [
        re.compile(r"(?i)\b(?:user|username|utilisateur|compte)\s*([:=]\s*([a-zA-Z0-9._-]+\b"),  # Noms d'utilisateurs génériques
        re.compile(r"(?i)(?:[a-zA-Z]:\\(?:users|utilisateurs)\\)([a-zA-Z0-9._-]+)"),  # Emails
        re.compile(r"(?i)(?:/home/)([a-zA-Z0-9._-]+)")
    ]