from uuid import UUID, uuid4 #randomizer
from datetime import datetime, timezone#date précise pour log
from typing import Optional , Any, Dict, List, Literal #décider précisément type des variables et retours
from enum import Enum #meilleure lisibilité pour les constantes

mon_uuid = uuid4() #uuid aléatoire v4=(128 bits aléatoires)
