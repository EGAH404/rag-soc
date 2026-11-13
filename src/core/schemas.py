from uuid import UUID, uuid4 #randomizer
from datetime import datetime, timezone #date précise pour log
from typing import Optional , Any, Dict, List, Literal #décider précisément type des variables et retours
from enum import Enum #meilleure lisibilité pour les constantes

mon_uuid = uuid4() #uuid aléatoire v4=(128 bits aléatoires)

# ==========================================
# 1. ÉNUMÉRATIONS (ROLES, TYPES)
# ==========================================

class UserRole(str, Enum):
    """Roles RBAC pour droits d'accès aux CHUNCKS et playbooks"""
    ANALYSTE_N1 = "analyste_1" #Triage initial, procédures d'escalade, playbooks publics/génériques et règles de détection standards
    ANALYSTE_N2 = "analyste_2" #Investigation approfondie, analyse forensique, playbooks d'investigation avancés
    ANALYSTE_N3 = "analyste_3" #Gestion des crises, remédiations sensibles, règles d'isolation réseau et playbooks critiques réservés au management ou au RSSI

class DocumentType(str, Enum):
    PDF = "pdf"
    YAML = "yaml"
    MARKDOWN = "markdown"

# =====================================================================
# 2. SCHÉMAS DE DOCUMENTS (Raw -> Cleaned)
# =====================================================================

class Rawdocuments:
