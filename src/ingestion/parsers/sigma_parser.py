"""
Module de parsing pour les règles de détection Sigma (YAML). 
Formate la règle sous forme de Markdown structuré pour l'indexation RAG. 
"""

from pathlib import Path 
from typing import List, Optional, Dict, Any 
import yaml 
from src.core.schemas import DocumentType, RawDocuments, UserRole

class SigmaParser:
    """
    Parseur de règles de détection Sigma (format YAML).
    """ 
    
    def parse_to_raw_document( 
            self, 
            yaml_path: str | Path, 
            allowed_roles: Optional[List[UserRole]] = None, 
            custom_metadata: Optional[Dict[str, Any]] = None,
    ) -> RawDocuments: 
        """Lit une règle Sigma YAML et la transforme en RawDocuments.
        Args: 
            yaml_path: Chemin du fichier YAML Sigma. 
            allowed_roles: Liste des rôles RBAC autorisés (par défaut Analyst N1). 
            custom_metadata: Métadonnées additionnelles. 

        Returns: 
            Instance de RawDocuments avec la règle formatée. """ 
        
        path = Path(yaml_path) 
        if not path.exists():
            raise FileNotFoundError(f"Fichier YAML introuvable : {yaml_path}") 
        if path.suffix.lower() not in [".yml", ".yaml"]: 
            raise ValueError(f"Le fichier n'est pas un YAML valide : {yaml_path}")

        # 1. Chargement sécurisé 
        with open(path, "r", encoding="utf-8") as f: 
            try: 
                data = yaml.safe_load(f) 
            except yaml.YAMLError as e: 
                raise ValueError(f"Erreur de syntaxe YAML dans {path.name} : {e}") 
            
        if not isinstance(data, dict): 
            raise ValueError(f"Le fichier {path.name} ne contient pas une règle Sigma valide.")

        # 2.