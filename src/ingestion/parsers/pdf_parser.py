""" 
Module de parsing PDF optimisé pour le RAG basé sur PyMuPDF4LLM. 
Extrait le contenu sous forme de Markdown structuré. 
"""

from pathlib import Path
from typing import List, Optional
import pymupdf4llm

from src.core.schemas import RawDocuments, DocumentType, UserRole

class PDFParser:
    """Parseur PDF utilisant PyMuPDF4LLM pour générer du Markdown propre pour RAG."""
    def __init__(self, write_images: bool = False):
        """ 
        Args: write_images: Si True, extrait et enregistre les images du PDF (optionnel). 
        """ 
        self.write_images = write_images

    def parse_to_raw_document(
        self,
        pdf_path: str | Path,
        allowed_roles: Optional[List[UserRole]] = None,
        custom_metadata: Optional[dict] = None
    ) -> RawDocuments:
        """Lit un PDF et le transforme en RawDocuments contenant du Markdown.
        Args:
            pdf_path: Chemin vers le fichier pdf_path
            allowed_roles: Liste des rôles RBAC autorisés. 
            custom_metadata: Métadonnées additionnelles. 

        Returns: 
            Instance de RawDocuments avec le contenu en Markdown. 
            """
        path = Path(pdf_path)

        if not path.exists():
            raise FileNotFoundError(f"Fichier PDF introuvable : {pdf_path}")
        if path.suffix.lower() != ".pdf":
            raise ValueError(f"Le fichier n'est pas un PDF valide : {pdf_path}")

        # Conversion du PDF en Markdown avec PyMuPDF4llm
        md_text = pymupdf4llm.to_markdown(
            doc = str(path),
            write_images = self.write_images
        )

        if not md_text or not md_text.strip():
            raise ValueError(f"Le fichier PDF {path.name} ne contient aucun texte extractible.")

        roles = allowed_roles or [UserRole.ANALYSTE_N1]

        metadata = {
            "file_name": path.name, 
            "file_size_bytes": path.stat().st_size, 
            "parser": "pymupdf4llm", **(custom_metadata or {}),
        }

        return RawDocuments(
            doc_path=str(path),
            doc_type=DocumentType.PDF,
            doc_content=md_text,
            allowed_roles=roles,
            metadata=metadata,
        )