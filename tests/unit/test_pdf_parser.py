from pathlib import Path 
import pypdf 
import pytest 
from src.core.schemas import UserRole 
from src.ingestion.pdf_parser import PDFParser 

@pytest.fixture 

def dummy_pdf(tmp_path: Path) -> Path: 
    """Crée un PDF temporaire simple pour les tests.""" 
    pdf_path = tmp_path / "playbook_test.pdf" 
    writer = pypdf.PdfWriter() 
    writer.add_blank_page(width=300, height=300) 
    
    with open(pdf_path, "wb") as f:
        writer.write(f) 
        return pdf_path 
    
    def test_pdf_parser_file_not_found(): 
        parser = PDFParser() 
        with pytest.raises(FileNotFoundError): 
            parser.parse_to_raw_document("invalid_path.pdf") 
    
    def test_pdf_parser_invalid_extension(tmp_path: Path): 
        fake_file = tmp_path / "not_a_pdf.txt" 
        fake_file.write_text("hello") 
        
        parser = PDFParser() 
        with pytest.raises(ValueError, match="pas un PDF valide"): 
            parser.parse_to_raw_document(fake_file)