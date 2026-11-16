import pytest
from pydantic import ValidationError
from datetime import datetime
from src.core.schemas import RawDocuments, CleanedDocuments, DocumentType, Chunk, UserRole

# ===================================================================== 
# 1\. Tests des Énumérations (Enums) 
# =====================================================================

def test_user_role_values():
    """Vérifie que les rôles RBAC SOC sont normalisés en minuscules pour Keycloak et Qdrant"""
    assert UserRole.ANALYSTE_N1.value == "analyste_1"
    assert UserRole.ANALYSTE_N2.value == "analyste_2"
    assert UserRole.ANALYSTE_N3.value == "analyste_3"
    # Vérifie que ce sont bien des chaînes comparables directement
    assert UserRole.ANALYSTE_N1 == "analyste_1"

def test_document_type_values():
    """Vérifie les formats de documents d'ingestion supportés."""
    assert DocumentType.PDF.value == "pdf"
    assert DocumentType.YAML.value == "yaml"
    assert DocumentType.MARKDOWN.value == "markdown"

# ===================================================================== 
# # 2\. Tests du modèle RawDocument 
# =====================================================================

def test_raw_document_valid():
    """Vérifie la création nominale de document brut extrait."""
    doc = RawDocuments(
        doc_path="data/raw/playbooks/ansii_ransomware.playbook.pdf",
        doc_type=DocumentType.PDF,
        doc_content="Contenu brut extrait du guide ANSSI contre les rançongiciels.",
        allowed_roles=[UserRole.ANALYSTE_N1, UserRole.ANALYSTE_N2],
        metadata={"author": "ANSSI", "version": "1.0"} 
    ) 
    
    # Vérifications des champs et des valeurs dynamiques générées 
    assert doc.doc_id is not None 
    assert len(doc.doc_id) > 0 
    assert isinstance(doc.ingested_at, datetime) 
    assert doc.doc_type == "pdf"
    assert "analyste_1" in doc.allowed_roles
    assert doc.metadata["author"] == "ANSSI" 

def test_raw_document_empty_text_rejected():
    """Vérifie que le validateur refuse un texte vide ou composé uniquement d'espaces."""
    with pytest.raises(ValidationError):
        RawDocuments(
            doc_path="data/raw/empty.pdf",
            doc_type=DocumentType.PDF,
            doc_content=" "  # Doit lever une erreur
        )

def test_raw_document_invalid_role_rejected():
    """Vérifie le rejet d'un rôle inconnu non prévu par le RBAC."""
    with pytest.raises(ValidationError):
        RawDocuments(
            doc_path="test.pdf",
            doc_type=DocumentType.PDF,
            doc_content="Texte valide",
            allowed_roles=["ADMIN_SUPER_ROOT"]  # Rôle invalide
        )

# ===================================================================== #
# 3\. Tests du modèle CleanedDocument #
# ===================================================================== #

def test_cleaned_document_valid():
    """Vérifie la création nominale d'un document assaini post-anonymisation."""
    cleaned = CleanedDocuments(
        raw_doc_id="123e4567-e89b-12d3-a456-426614174000",
        raw_doc_path="data/raw/rules/sigma_powershell.yml",
        raw_doc_type=DocumentType.YAML,
        cleaned_doc_content="Alerte déclenchée par <USER> depuis adresse <IP_PRIVATE>.",
        pii_stats={"IP_PRIVATE": 1, "USER": 1},
        allowed_roles=[UserRole.ANALYSTE_N1]
    ) 
    
    assert cleaned.cleaned_doc_id is not None 
    assert cleaned.raw_doc_id == "123e4567-e89b-12d3-a456-426614174000" 
    assert cleaned.pii_stats["IP_PRIVATE"] == 1 
    assert "<IP_PRIVATE>" in cleaned.cleaned_doc_content
    assert isinstance(cleaned.cleaned_at, datetime)

def test_cleaned_document_empty_text_rejected():
    """Vérifie le rejet si le texte anonymisé est vide."""
    with pytest.raises(ValidationError):
        CleanedDocuments(
            raw_doc_id="doc-123",
            raw_doc_path="test.yml",
            raw_doc_type=DocumentType.YAML,
            cleaned_doc_content="",
            pii_stats={}
        )

# ===================================================================== #
# 4\. Tests du modèle Chunk #
# ===================================================================== #

def test_chunk_creation_without_vector():
    """Vérifie qu'Aurélien peut générer des chunks sans renseigner le vecteur immédiat."""
    chunk = Chunk(
        cleaned_doc_id="doc-parent-uuid",
        chunk_index=0,
        chunk_content="Étape 1 : Isoler immédiatement la machine compromise du réseau local.",
        allowed_roles=[UserRole.ANALYSTE_N1, UserRole.ANALYSTE_N2, UserRole.ANALYSTE_N3]
    )
    assert chunk.chunk_id is not None
    assert chunk.dense_vector is None
    assert chunk.chunk_index == 0
    assert "analyste_1" in chunk.allowed_roles

def test_chunk_unique_ids():
    """Vérifie que la lambda default_factory génère bien des IDs distincts pour chaque chunk."""
    chunk1 = Chunk(cleaned_doc_id="doc-1", chunk_index=0, chunk_content="Chunk A")
    chunk2 = Chunk(cleaned_doc_id="doc-1", chunk_index=1, chunk_content="Chunk B")
    assert chunk1.chunk_id != chunk2.chunk_id

def test_chunk_with_valid_dense_vector():
    """Vérifie qu'un vecteur bge-m3 de dimension exacte 1024 est accepté (phase Jérôme)."""
    fake_bge_m3_vector = [0.01] * 1024
    chunk = Chunk(
        cleaned_doc_id="doc-parent-uuid",
        chunk_index=1,
        chunk_content="Segment pour analyse forensique avancée.",
        dense_vector=fake_bge_m3_vector,
        allowed_roles=[UserRole.ANALYSTE_N2]
    )
    assert chunk.dense_vector is not None
    assert len(chunk.dense_vector) == 1024

def test_chunk_with_invalid_dense_vector_dimension():
    """Vérifie que le validateur rejette toute dimension vectorielle différente de 1024."""
    bad_vector = [0.1] * 512  # Mauvaise dimension (ex: ada-002 ou autre)
    with pytest.raises(ValidationError):
        Chunk(
            cleaned_doc_id="doc-parent-uuid",
            chunk_index=2,
            chunk_content="Segment de test",
            dense_vector=bad_vector
        )

def test_chunk_negative_index_rejected():
    """Vérifie que la contrainte ge=0 sur le chunk_index rejette les valeurs négatives."""
    with pytest.raises(ValidationError):
        Chunk(
            cleaned_doc_id="doc-parent-uuid",
            chunk_index=-1,
            chunk_content="Segment invalide"
        )