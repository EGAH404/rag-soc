"""
Module de parsing pour les règles de détection Sigma (YAML). 
Formate la règle sous forme de Markdown structuré pour l'indexation RAG. 
"""

from pathlib import Path 
from typing import List, Optional, Dict, Any 
import yaml 
from src.core.schemas import DocumentType, RawDocuments, UserRole