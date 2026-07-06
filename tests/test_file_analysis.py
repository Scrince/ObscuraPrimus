import json
import sqlite3
import tempfile
import unittest
import zipfile
from pathlib import Path

from obscuraprimus.case_db import dashboard
from obscuraprimus.file_analysis import (
    add_evidence,
    analyze_file,
    analyze_path,
    carve_embedded_files,
    compare_files,
    create_case,
    extract_strings,
    hex_preview,
    search_hex,
    strip_jpeg_exif,
    write_analysis_report,
)
from obscuraprimus.health import portable_health
from obscuraprimus.plugins import available_plugins


class FileAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_magic_hash_strings_iocs_and_signature_mismatch(self):
        disguised = self.root / "sample.jpg"
        disguised.write_bytes(b"PK\x03\x04hello https://example.com admin@example.com 192.168.1.1")

        result = analyze_file(disguised)

        self.assertEqual(result.magic_type, "ZIP/Office container")
        self.assertTrue(result.signature_mismatch)
        self.assertIn("sha256", result.hashes)
        self.assertIn("urls", result.iocs)
        self.assertGreater(result.risk_score, 0)

    def test_hex_preview_and_search(self):
        target = self.root / "data.bin"
        target.write_bytes(b"abcdef" * 20)

        self.assertIn("00000000", hex_preview(target))
        self.assertEqual(search_hex(target, b"cde")[:1], [2])

    def test_zip_container_and_office_macro_detection(self):
        doc = self.root / "macro.docx"
        with zipfile.ZipFile(doc, "w") as archive:
            archive.writestr("word/document.xml", "<w:document/>")
            archive.writestr("word/vbaProject.bin", b"macro")
            archive.writestr("_rels/.rels", '<Relationship Target="https://example.com/template.dotm" TargetMode="External"/>')
            archive.writestr("word/embeddings/oleObject1.bin", b"ole")

        result = analyze_file(doc)

        self.assertEqual(result.container["type"], "zip")
        self.assertTrue(result.metadata["office_container"])
        self.assertTrue(result.metadata["macro_possible"])
        self.assertTrue(result.metadata["external_links"])
        self.assertTrue(result.metadata["embedded_objects"])

    def test_pdf_lnk_msi_and_sqlite_inspection(self):
        pdf = self.root / "doc.pdf"
        pdf.write_bytes(b"%PDF-1.7\n1 0 obj << /OpenAction 2 0 R /JavaScript 3 0 R /EmbeddedFile 4 0 R >> endobj\nstream\nx\nendstream\n%%EOF")
        self.assertTrue(analyze_file(pdf).metadata["javascript"])
        self.assertTrue(analyze_file(pdf).metadata["embedded_files"])

        lnk = self.root / "shortcut.lnk"
        lnk.write_bytes(b"\x4c\x00\x00\x00" + bytes.fromhex("0114020000000000C000000000000046") + b"\x01\x00\x00\x00" + b"\x00" * 64)
        self.assertTrue(analyze_file(lnk).metadata["lnk"]["valid_lnk"])

        msi = self.root / "setup.msi"
        msi.write_bytes(bytes.fromhex("D0CF11E0A1B11AE1") + b"\x00" * 128)
        self.assertTrue(analyze_file(msi).metadata["msi"]["compound_file_signature"])

        db = self.root / "browser.sqlite"
        con = sqlite3.connect(db)
        try:
            con.execute("create table urls(id integer primary key, url text)")
            con.commit()
        finally:
            con.close()
        tables = analyze_file(db).metadata["sqlite"]["tables"]
        self.assertEqual(tables[0]["name"], "urls")

    def test_reports_and_case_manifest(self):
        target = self.root / "note.txt"
        target.write_text("hello analyst", encoding="utf-8")
        results = analyze_path(self.root)
        json_report = self.root / "report.json"
        html_report = self.root / "report.html"
        csv_report = self.root / "report.csv"

        write_analysis_report(results, str(json_report))
        write_analysis_report(results, str(html_report))
        write_analysis_report(results, str(csv_report))

        self.assertIn("note.txt", json_report.read_text(encoding="utf-8"))
        self.assertIn("<html", html_report.read_text(encoding="utf-8"))
        self.assertIn("sha256", csv_report.read_text(encoding="utf-8"))

        case_dir = create_case(self.root / "case", "demo")
        entry = add_evidence(case_dir, target, ["tag"], "note")
        manifest = json.loads((case_dir / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(entry["sha256"], manifest["evidence"][0]["sha256"])
        self.assertTrue((case_dir / "audit.log").exists())
        self.assertEqual(dashboard(case_dir)["evidence_count"], 1)

    def test_utf16_strings(self):
        strings = extract_strings("secret".encode("utf-16le"))
        self.assertIn("secret", strings)

    def test_carving_compare_exif_strip_health_and_plugins(self):
        carrier = self.root / "carrier.bin"
        embedded_png = b"\x89PNG\r\n\x1a\npayloadIEND\xaeB`\x82"
        carrier.write_bytes(b"prefix" + embedded_png + b"suffix")
        carved = carve_embedded_files(carrier, self.root / "carved")
        self.assertEqual(carved[0]["type"], "png")

        left = self.root / "left.bin"
        right = self.root / "right.bin"
        left.write_bytes(b"abc")
        right.write_bytes(b"abd")
        self.assertEqual(compare_files(left, right)["diffs"][0]["offset"], 2)

        jpg = self.root / "photo.jpg"
        jpg.write_bytes(b"\xff\xd8\xff\xe1\x00\x10Exif\x00\x00payload\xff\xdaimage\xff\xd9")
        stripped = self.root / "stripped.jpg"
        strip_jpeg_exif(jpg, stripped)
        self.assertNotIn(b"Exif", stripped.read_bytes())

        self.assertIn("data_writable", portable_health())
        self.assertTrue(available_plugins())


if __name__ == "__main__":
    unittest.main()
