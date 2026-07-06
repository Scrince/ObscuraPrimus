import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import wave
from pathlib import Path

from obscuraprimus.png_codec import PngImage, write_png
from obscuraprimus.forensics import scan_path
from obscuraprimus.stego_engine import PREFIX_SIZE, CapacityError, EmbedOptions, StegoError, embed_file, estimate_capacity, extract_file


FIXTURE_DIR = Path(__file__).parent / "fixtures"


class StegoRoundTripTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="obscuraprimus-test-"))

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_bmp_roundtrip_with_compression_encryption_and_adaptive_mode(self):
        cover = FIXTURE_DIR / "sample.bmp"
        secret = self.root / "secret.txt"
        stego = self.root / "stego.bmp"
        extracted_dir = self.root / "out"
        extracted_dir.mkdir()

        secret.write_text("ObscuraPrimus test payload.\n" * 24, encoding="utf-8")

        embed_file(
            str(cover),
            str(secret),
            str(stego),
            EmbedOptions(
                compress=True,
                encryption="AES-256-GCM",
                password="correct horse battery staple",
                adaptive=True,
            ),
        )

        result = extract_file(
            str(stego),
            str(extracted_dir),
            password="correct horse battery staple",
            output_name="recovered.txt",
        )

        self.assertEqual(result.filename, "recovered.txt")
        self.assertEqual((extracted_dir / "recovered.txt").read_bytes(), secret.read_bytes())

    def test_wav_roundtrip_with_spread_mode(self):
        cover = FIXTURE_DIR / "sample.wav"
        secret = self.root / "secret.bin"
        stego = self.root / "stego.wav"
        extracted_dir = self.root / "out"
        extracted_dir.mkdir()
        secret.write_bytes(bytes(range(64)) * 5)

        embed_file(
            str(cover),
            str(secret),
            str(stego),
            EmbedOptions(compress=False, encryption="None", password="", adaptive=False, spread=True),
        )
        extract_file(str(stego), str(extracted_dir), output_name="recovered.bin")
        self.assertEqual((extracted_dir / "recovered.bin").read_bytes(), secret.read_bytes())

    def test_png_roundtrip(self):
        cover = self.root / "cover.png"
        secret = self.root / "secret.txt"
        stego = self.root / "stego.png"
        extracted_dir = self.root / "out"
        extracted_dir.mkdir()
        pixels = bytes((i * 19 + 41) % 256 for i in range(180 * 180 * 4))
        image = PngImage(180, 180, 8, 6, 0, 0, 0, pixels, [(b"IHDR", struct.pack(">IIBBBBB", 180, 180, 8, 6, 0, 0, 0))], [(b"IEND", b"")])
        write_png(image, cover)
        secret.write_text("PNG payload\n" * 20, encoding="utf-8")

        embed_file(str(cover), str(secret), str(stego), EmbedOptions(compress=True, adaptive=True, spread=True))
        extract_file(str(stego), str(extracted_dir), output_name="recovered.txt")
        self.assertEqual((extracted_dir / "recovered.txt").read_bytes(), secret.read_bytes())

    def test_wrong_password_fails(self):
        cover = FIXTURE_DIR / "sample.bmp"
        secret = self.root / "secret.txt"
        stego = self.root / "stego.bmp"
        secret.write_text("private", encoding="utf-8")

        embed_file(str(cover), str(secret), str(stego), EmbedOptions(encryption="AES-256-GCM", password="right", adaptive=True))

        with self.assertRaises(StegoError):
            extract_file(str(stego), str(self.root), password="wrong", output_name="bad.txt")
        self.assertFalse((self.root / "bad.txt").exists())

    def test_encrypted_metadata_hides_filename_and_extracts_with_password(self):
        cover = FIXTURE_DIR / "sample.bmp"
        secret = self.root / "private-name.txt"
        stego = self.root / "stego.bmp"
        secret.write_text("private metadata", encoding="utf-8")

        embed_file(str(cover), str(secret), str(stego), EmbedOptions(encryption="AES-256-GCM", password="right"))
        raw = stego.read_bytes()
        self.assertNotIn(b"private-name.txt", raw)

        result = extract_file(str(stego), str(self.root), password="right")
        self.assertEqual(result.filename, "private-name.txt")
        self.assertEqual((self.root / "private-name.txt").read_text(encoding="utf-8"), "private metadata")

    def test_scrypt_and_separate_stego_key(self):
        cover = FIXTURE_DIR / "sample.bmp"
        secret = self.root / "secret.txt"
        stego = self.root / "stego.bmp"
        secret.write_text("scrypt payload", encoding="utf-8")

        embed_file(
            str(cover),
            str(secret),
            str(stego),
            EmbedOptions(
                encryption="AES-256-GCM",
                password="encryption-password",
                stego_key="carrier-password",
                adaptive=True,
                spread=True,
                kdf="scrypt",
            ),
        )

        with self.assertRaises(StegoError):
            extract_file(str(stego), str(self.root), password="encryption-password", output_name="wrong.txt")

        extract_file(
            str(stego),
            str(self.root),
            password="encryption-password",
            output_name="right.txt",
            stego_key="carrier-password",
        )
        self.assertEqual((self.root / "right.txt").read_text(encoding="utf-8"), "scrypt payload")

    def test_density_presets_change_capacity_and_roundtrip(self):
        cover = FIXTURE_DIR / "sample.bmp"
        secret = self.root / "secret.txt"
        stego = self.root / "stego.bmp"
        secret.write_text("density preset", encoding="utf-8")

        maximum = estimate_capacity(str(cover), density="maximum")
        balanced = estimate_capacity(str(cover), density="balanced")
        stealth = estimate_capacity(str(cover), density="stealth")
        self.assertGreater(maximum, balanced)
        self.assertGreater(balanced, stealth)

        embed_file(str(cover), str(secret), str(stego), EmbedOptions(compress=False, density="stealth", spread=True))
        extract_file(str(stego), str(self.root), output_name="density.txt")
        self.assertEqual((self.root / "density.txt").read_text(encoding="utf-8"), "density preset")

    def test_forensic_scan_finds_embedded_payload(self):
        cover = FIXTURE_DIR / "sample.bmp"
        secret = self.root / "secret.txt"
        stego = self.root / "stego.bmp"
        secret.write_text("find me", encoding="utf-8")

        embed_file(str(cover), str(secret), str(stego), EmbedOptions(compress=False))
        findings = scan_path(str(stego))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, "suspect")
        self.assertEqual(findings[0].confidence, "high")
        self.assertGreaterEqual(findings[0].risk_score, 90)

    def test_forensic_json_report(self):
        cover = FIXTURE_DIR / "sample.bmp"
        secret = self.root / "secret.txt"
        stego = self.root / "stego.bmp"
        report = self.root / "report.json"
        secret.write_text("json report", encoding="utf-8")
        embed_file(str(cover), str(secret), str(stego), EmbedOptions(compress=False))
        findings = scan_path(str(stego))
        from obscuraprimus.forensics import write_report

        write_report(findings, str(report))
        text = report.read_text(encoding="utf-8")
        self.assertIn('"risk_score"', text)
        self.assertIn('"status": "suspect"', text)

    def test_cli_capacity_and_scan(self):
        result = subprocess.run(
            [sys.executable, "-m", "obscuraprimus", "capacity", "--cover", str(FIXTURE_DIR / "sample.bmp")],
            cwd=Path(__file__).parents[1],
            text=True,
            capture_output=True,
            check=True,
        )
        self.assertGreater(int(result.stdout.strip()), 0)

        stealth = subprocess.run(
            [sys.executable, "-m", "obscuraprimus", "capacity", "--cover", str(FIXTURE_DIR / "sample.bmp"), "--density", "stealth"],
            cwd=Path(__file__).parents[1],
            text=True,
            capture_output=True,
            check=True,
        )
        self.assertLess(int(stealth.stdout.strip()), int(result.stdout.strip()))

        scan = subprocess.run(
            [sys.executable, "-m", "obscuraprimus", "scan", str(FIXTURE_DIR)],
            cwd=Path(__file__).parents[1],
            text=True,
            capture_output=True,
            check=True,
        )
        self.assertIn("CLEAN", scan.stdout)

    def test_corrupted_payload_fails_without_partial_output(self):
        cover = FIXTURE_DIR / "sample.bmp"
        secret = self.root / "secret.txt"
        stego = self.root / "stego.bmp"
        secret.write_text("checksum me", encoding="utf-8")
        embed_file(str(cover), str(secret), str(stego), EmbedOptions(compress=False, adaptive=False))
        data = bytearray(stego.read_bytes())
        data[54 + PREFIX_SIZE * 8 + 128] ^= 1
        stego.write_bytes(data)

        with self.assertRaises(StegoError):
            extract_file(str(stego), str(self.root), output_name="corrupt.txt")
        self.assertFalse((self.root / "corrupt.txt").exists())

    def test_oversized_payload_fails(self):
        cover = self.root / "tiny.bmp"
        secret = self.root / "large.bin"
        _write_bmp_cover(cover, 24, 24)
        secret.write_bytes(b"x" * 5000)
        with self.assertRaises(CapacityError):
            embed_file(str(cover), str(secret), str(self.root / "stego.bmp"), EmbedOptions(compress=False))

    def test_malformed_cover_inputs_fail_cleanly(self):
        bad_bmp = self.root / "bad.bmp"
        bad_png = self.root / "bad.png"
        secret = self.root / "secret.txt"
        bad_bmp.write_bytes(b"BM too short")
        bad_png.write_bytes(b"not a png")
        secret.write_text("payload", encoding="utf-8")

        with self.assertRaises(Exception):
            embed_file(str(bad_bmp), str(secret), str(self.root / "out.bmp"), EmbedOptions())
        with self.assertRaises(Exception):
            embed_file(str(bad_png), str(secret), str(self.root / "out.png"), EmbedOptions())


def _write_bmp_cover(path: Path, width: int, height: int):
    row_size = ((24 * width + 31) // 32) * 4
    pixel_size = row_size * height
    file_size = 54 + pixel_size
    header = bytearray()
    header += b"BM"
    header += struct.pack("<IHHI", file_size, 0, 0, 54)
    header += struct.pack("<IiiHHIIiiII", 40, width, height, 1, 24, 0, pixel_size, 2835, 2835, 0, 0)
    pixels = bytearray((i * 37 + 91) % 256 for i in range(pixel_size))
    path.write_bytes(header + pixels)


def _write_wav_cover(path: Path):
    with wave.open(str(path), "wb") as writer:
        writer.setnchannels(1)
        writer.setsampwidth(2)
        writer.setframerate(44100)
        frames = bytearray()
        for i in range(44100):
            sample = int(12000 * ((i % 100) / 50 - 1))
            frames.extend(struct.pack("<h", sample))
        writer.writeframes(frames)


def setUpModule():
    FIXTURE_DIR.mkdir(exist_ok=True)
    bmp = FIXTURE_DIR / "sample.bmp"
    wav = FIXTURE_DIR / "sample.wav"
    if not bmp.exists():
        _write_bmp_cover(bmp, 260, 260)
    if not wav.exists():
        _write_wav_cover(wav)


if __name__ == "__main__":
    unittest.main()
