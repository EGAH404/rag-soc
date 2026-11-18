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
    ) -> RawDocuments
    
         