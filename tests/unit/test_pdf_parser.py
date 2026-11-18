from pathlib import Path 
import pytest 
from src.ingestion.parsers.pdf_parser import PDFParser 


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


def test_pdf_parser_returns_raw_document_with_metadata(tmp_path: Path, monkeypatch):
    pdf_file = tmp_path / "playbook.pdf"
    pdf_file.write_bytes(b"mock pdf")
    monkeypatch.setattr(
        "src.ingestion.parsers.pdf_parser.pymupdf4llm.to_markdown",
        lambda **kwargs: "# Extracted text",
    )

    document = PDFParser().parse_to_raw_document(pdf_file)

    assert document.doc_content == "# Extracted text"
    assert document.metadata["file_name"] == "playbook.pdf"
    assert document.metadata["parser"] == "pymupdf4llm"