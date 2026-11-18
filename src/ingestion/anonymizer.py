""" 
Module d'anonymisation et de désensibilisation PII (Personally Identifiable Information). 
Traite les documents bruts (RawDocument) pour produire des documents nettoyés (CleanedDocument). 
"""

import ipaddress
import re
from typing import Dict
from src.core.schemas import RawDocuments, CleanedDocuments

class Anonymizer:
    """
    Anonymiseur de données sensibles pour le pipeline d'ingestion SOC. 
    Masque les adresses IP privées (RFC 1918), les e-mails et les comptes utilisateurs. 
    """

    # Motif adresses mail
    EMAIL_PATTERN = re.compile(r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.[A-Za-z]{2,}\b")

    # Motif IPV4
    IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    # Motifs courants noms d'utilisateurs windows et linux
    USER_PATTERNS = [
        re.compile(r"(?i)\b(?:user|username|utilisateur|compte)\s*[:=]\s*([a-zA-Z0-9._-]+)\b"),
        re.compile(r"(?i)[a-zA-Z]:\\(?:Users|Utilisateurs)\\([a-zA-Z0-9._-]+)"),
        re.compile(r"(?i)(?:/home/)([a-zA-Z0-9._-]+)")
    ]

    def __init__(self):
        pass  # Aucun état interne nécessaire pour l'instant

    def _mask_email(self, text: str) -> tuple[str, int]:
        """Remplissage des adresses e-mail par <EMAIL>"""
        matches = self.EMAIL_PATTERN.findall(text)
        count = len(matches)
        sanitized_text = self.EMAIL_PATTERN.sub("<EMAIL>", text)
        return sanitized_text, count

    def _mask_private_ip(self, text: str) -> tuple[str, int]:
        """
        Remplace uniquement les adresses IP privées (RFC 1918 / Loopback) par <PRIVATE_IP>
        Conserve les adresses IP publiques nécessaires à la Threat Intelligence
        """
        count = 0

        def replace_ip(match: re.Match) -> str:
            nonlocal count
            ip_str = match.group(0)
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                if ip_obj.is_private or ip_obj.is_loopback:
                    count += 1
                    return "<PRIVATE_IP>"
                return ip_str # Conserve les IP publiques pour VirusTotal/AbuseIPDB
            except ValueError:
                return ip_str
        sanitized_text = self.IPV4_PATTERN.sub(replace_ip, text)
        return sanitized_text, count

    def _mask_user(self, text: str) -> tuple[str, int]:
        """Remplace les noms d'utilisateurs par <USER>"""
        count = 0
        sanitized_text = text

        for pattern in self.USER_PATTERNS:
            def replace_user(match: re.Match) -> str:
                nonlocal count
                count += 1
                return (
                    match.string[match.start():match.start(1)]
                    + "<USER>"
                    + match.string[match.end(1):match.end()]
                )

            sanitized_text = pattern.sub(replace_user, sanitized_text)
        return sanitized_text, count

    def anonymize_text(self, text: str) -> tuple[str, Dict[str, int]]:
        """
        Applique toutes les règles d'assainissement sur une chaîne de caractères brute. 
        Retourne le texte anonymisé et les statistiques d'audit. 
        """
        stats: Dict[str, int] = {}

        # Masquage des e-mails
        text, email_count = self._mask_email(text)
        if email_count > 0:
            stats["EMAIL"] = email_count

        # Masquage des adresses IP privées
        text, ip_count = self._mask_private_ip(text)
        if ip_count > 0: 
            stats["IP_PRIVATE"] = ip_count

        # Masquage des noms d'utilisateurs
        text, user_count = self._mask_user(text)
        if user_count > 0:
            stats["USER"] = user_count

        return text, stats

    
    def process_document(self, raw_doc: RawDocuments) -> CleanedDocuments: 
        """ Transforme un RawDocument en CleanedDocument avec traçabilité complète. """ 
        cleaned_doc_content, pii_stats = self.anonymize_text(raw_doc.doc_content)
        return CleanedDocuments(raw_doc_id=raw_doc.doc_id,
                                raw_doc_path=raw_doc.doc_path,
                                raw_doc_type=raw_doc.doc_type,
                                cleaned_doc_content=cleaned_doc_content,
                                pii_stats=pii_stats,
                                allowed_roles=raw_doc.allowed_roles, # Propagation du RBAC 
                                metadata={ **raw_doc.metadata, 
                                          "anonymization_performed": True 
                                } 
        )
    