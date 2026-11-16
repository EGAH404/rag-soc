import pytest
from src.core.schemas import RawDocuments, DocumentType, UserRole 
from src.ingestion.anonymizer import Anonymizer 

@pytest.fixture 

def anonymizer(): 
    return Anonymizer() 

def test_mask_private_ip(anonymizer): 
    text = "Machine locale 192.168.1.50 et passerelle 10.0.0.1 avec boucle 127.0.0.1" 
    cleaned, stats = anonymizer.anonymize_text(text) 
    assert "192.168.1.50" not in cleaned 
    assert "10.0.0.1" not in cleaned 
    assert "127.0.0.1" not in cleaned 
    assert cleaned.count("<PRIVATE_IP>") == 3
    assert stats["IP_PRIVATE"] == 3 
    
def test_keep_public_ips_intact(anonymizer): 
    # Les IP publiques sont des IoC qui ne doivent pas être masquées 
    text = "Attaque DDoS observée depuis 8.8.8.8 et C2 hébergé sur 185.220.101.5" 
    cleaned, stats = anonymizer.anonymize_text(text) 

    assert "8.8.8.8" in cleaned 
    assert "185.220.101.5" in cleaned 
    assert stats.get("IP_PRIVATE", 0) == 0 

def test_mask_emails(anonymizer): 
    text = "Alerte reçue de jean.dupont@entreprise.corp concernant un phishing." 
    cleaned, stats = anonymizer.anonymize_text(text) 

    assert "jean.dupont@entreprise.corp" not in cleaned 
    assert "<EMAIL>" in cleaned
    assert stats["EMAIL"] == 1

def test_process_raw_document(anonymizer):
    raw_doc = RawDocuments(
        doc_path="data/raw/alert.txt",
        doc_type=DocumentType.MARKDOWN,
        doc_content="Compte user: jdoe compromis sur hôte 172.16.5.10.",
        allowed_roles=[UserRole.ANALYSTE_N1]
    )

    cleaned_doc = anonymizer.process_document(raw_doc)

    assert cleaned_doc.raw_doc_id == raw_doc.doc_id
    assert "172.16.5.10" not in cleaned_doc.cleaned_doc_content
    assert "<PRIVATE_IP>" in cleaned_doc.cleaned_doc_content
    assert "<USER>" in cleaned_doc.cleaned_doc_content
    assert cleaned_doc.pii_stats["IP_PRIVATE"] == 1
    assert "analyste_1" in cleaned_doc.allowed_roles