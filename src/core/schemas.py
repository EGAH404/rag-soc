from uuid import UUID, uuid4 #randomizer
from datetime import datetime, timezone #date précise pour log
from typing import Optional , Any, Dict, List, Literal #décider précisément type des variables et retours
from enum import Enum #meilleure lisibilité pour les constantes
from pydantic import BaseModel, Field, field_validator, ConfigDict

mon_uuid = uuid4() #uuid aléatoire v4=(128 bits aléatoires)

# ==========================================
# 1. ÉNUMÉRATIONS (ROLES, TYPES)
# ==========================================

class UserRole(str, Enum):
    """Roles RBAC pour droits d'accès aux CHUNKS et playbooks"""
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

class RawDocuments(BaseModel):
    """représentation des documents bruts (raw) avant anonymisation et chunking"""
    # ID unique du document
    doc_id: str = Field(default_factory=lambda: str(uuid4()), description="Identifiant unique du document")

    # Chemin ou URI du document brut
    doc_path: str = Field(..., description="Chemin source du document brut")

    # Format du document
    doc_type: DocumentType = Field(..., description="Format d'origine du document")

    # Contenu brut du document (non anonymisé)
    doc_content: str = Field(..., description="Contenu brut du document")

    # Horodatage d'ingestion du document
    ingested_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Horodatage d'ingestion du document")

    # Roles autorisés à accéder au document
    allowed_roles: List[UserRole] = Field(default=[UserRole.ANALYSTE_N1, UserRole.ANALYSTE_N2, UserRole.ANALYSTE_N3], description="Roles autorisés à accéder au aux chunks issus du document")

    # Métadonnées d'origine du document (ex: auteur, source, etc.)
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Métadonnées d'extraction (source ANSSI/NIST, tags de détection, titre)")

    # config pydantic v2
    model_config = ConfigDict(
        use_enum_values = True, # permet de sérialiser les enums en chaines ordinaires plutôt qu'en objets Enum
        validate_assignment = True, # permet de valider les types en cas de modification d'attribus
        extra = "forbid" # Rejette tout champs non déclaré (sécurité)
    )

    @field_validator("doc_content")
    @classmethod
    def validate_doc_content_not_empty(cls, v:str) -> str:
        """Empêche l'ingestion d'un document sans texte exploitable."""
        if not v or not v.strip():
            raise ValueError("Le contenu textuel extrait (raw_text) ne peut pas être vide.")
        return v

class CleanedDocuments(BaseModel):
    """document apres extraction et anonymisation des PII, prêt pour le chunking et l'indexation"""
    # ID unique document propre
    cleaned_doc_id: str = Field(default_factory=lambda: str(uuid4()), description="Identifiant unique du document nettoyé")

    # tracabilité vers document brut
    raw_doc_id: str = Field(..., description="Identifiant du document brut d'origine")
    raw_doc_path: str = Field(..., description="Chemin source du document brut d'origine")
    raw_doc_type: DocumentType = Field(..., description="Format d'origine du document brut")

    # Contenus sans PII
    cleaned_doc_content: str = Field(..., description="Contenu nsans PII (données sensibles sont remplacées par des balises)")

    # audit de trail de l'anonymisation
    pii_stats: Dict[str, int] = Field(default_factory=dict, description="Comptage des éléments masqués (ex: {'IP\_PRIVATE': 3, 'EMAIL': 1}")

    # Horodatage de l'anonymisation
    cleaned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="date heure UTC anonymisation")

    # Heritage des roles autorisés à accéder au document nettoyé
    allowed_roles: List[UserRole] = Field(default=[UserRole.ANALYSTE_N1, UserRole.ANALYSTE_N2, UserRole.ANALYSTE_N3], description="Roles autorisés à accéder au aux futures chunks issus du document nettoyé")

    metadata: Dict[str, Any] = Field( default_factory=dict, description="Métadonnées enrichies (source, tag MITRE, statut d'audit)" )

    model_config = ConfigDict( use_enum_values=True, validate_assignment=True, extra="forbid" )
    
    @field_validator("cleaned_doc_content") 
    @classmethod 
    def validate_text_not_empty(cls, v: str) -> str :
        """S'assure que le texte anonymisé n'est pas vide.""" 
        if not v or not v.strip(): 
            raise ValueError("Le texte anonymisé ne peut pas être vide.") 
        return v