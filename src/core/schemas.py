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

class Chunk(BaseModel):
    """
    Unité élémentaire de recherche indexée dans Qdrant. 
    Produit par le chunking, enrichi par l'embedding, et filtré par les rôles RBAC.
    """
    # ID unique du chunk
    chunk_id: str= Field(default_factory=lambda: str(uuid4()), description="Identifiant unique du chunk")

    # tracabilité vers le document nettoyé
    cleaned_doc_id: str = Field(..., description="identifiant du document nettoyé d'origine")

    # position séquentielle du chunk dans le doc
    chunk_index: int = Field(..., ge=0,description="Index du chunk dans le document nettoyé (0-based)")

    # contenu textuel
    chunk_content: str = Field(..., description="segment de text pret pour l'indexation")

    # Vecteurs Qdrant remplissage par Jérome
    dense_vector: Optional[List[float]] = Field(default=None, description="Embedding dense bge-m3 (dimension 1024)")
    sparse_vector: Optional[Dict[int, float]] = Field(default=None, description="Vecteur creux optionnel pour la recherche lexicale/hybride BM25")

    # sécurité et filtrage RBAC
    allowed_roles: List[UserRole] = Field(default=[UserRole.ANALYSTE_N1, UserRole.ANALYSTE_N2, UserRole.ANALYSTE_N3], description="Roles autorisés recuperer chunk lors de recherche vectorielle")

    # Métadonnées de charge utile (payload) 
    metadata: Dict[str, Any] = Field( default_factory=dict, description="Métadonnées d'indexation (titre, type de règle, tag MITRE, etc.)" ) 

    model_config = ConfigDict( use_enum_values=True, validate_assignment=True, extra="forbid" )

    @field_validator("chunk_content")
    @classmethod
    def validate_chunk_content_not_empty(cls, v: str) -> str:
        """S'assure que le contenu du chunk n'est pas vide."""
        if not v or not v.strip():
            raise ValueError("Le contenu du chunk ne peut pas être vide.")
        return v

    @field_validator("dense_vector")
    @classmethod
    def validate_dense_vector_dimension(cls, v: Optional[List[float]]) -> Optional[List[float]]:
        """S'assure que le vecteur dense a la dimension correcte (1024)."""
        if v is not None and len(v) != 1024:
            raise ValueError(f"La dimension du vecteur dense ({len(v)}) est invalide. Attendu : 1024 pour bge-m3.")
        return v

    