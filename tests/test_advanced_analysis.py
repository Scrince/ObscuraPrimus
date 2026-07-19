import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from obscuraprimus.advanced_analysis import (
    analyze_path_isolated,
    anomaly_score,
    byte_histogram,
    carving_preview,
    import_immutable_evidence,
    export_case_bundle,
    import_case_bundle,
    inspect_browser_artifact,
    inspect_raw_image,
    inspect_windows_artifact,
    onboarding_sample_case,
    search_case,
    validate_sigma_rule,
    validate_yara_rules,
    virtual_hex_page,
    write_example_plugin,
)
from obscuraprimus.case_db import create_finding, search_fts, store_analysis_results, update_finding
from obscuraprimus.flac_codec import inspect_flac
from obscuraprimus.plugins import discover_plugins, run_matching_plugins
from obscuraprimus.stego_engine import EmbedOptions, embed_file, estimate_capacity, extract_file


class AdvancedAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_flac_application_round_trip(self):
        cover = self.root / "cover.flac"
        secret = self.root / "secret.txt"
        stego = self.root / "stego.flac"
        out = self.root / "out"
        cover.write_bytes(b"fLaC" + bytes([0x80]) + (34).to_bytes(3, "big") + b"\x00" * 34 + b"\xff\xf8audioframes")
        secret.write_text("hidden in a valid FLAC metadata block", encoding="utf-8")

        self.assertGreater(estimate_capacity(str(cover)), 1000)
        # FLAC APPLICATION-block stego requires encryption (payload is discoverable otherwise).
        options = EmbedOptions(
            compress=False,
            encryption="AES-256-GCM",
            password="flac-test-password",
        )
        embed_file(str(cover), str(secret), str(stego), options)
        result = extract_file(str(stego), str(out), password="flac-test-password")

        self.assertEqual((out / result.filename).read_text(encoding="utf-8"), "hidden in a valid FLAC metadata block")
        self.assertTrue(inspect_flac(stego)["obscuraprimus_payload"])

    def test_immutable_evidence_case_search_and_sample(self):
        case_dir = self.root / "case"
        evidence = self.root / "ioc.txt"
        evidence.write_text("https://example.com analyst@example.com", encoding="utf-8")

        entry = import_immutable_evidence(case_dir, evidence, ["ioc"], "note")
        matches = search_case(case_dir, "example.com")
        sample = onboarding_sample_case(self.root / "sample")

        self.assertTrue(Path(entry["copy"]).exists())
        self.assertTrue(matches)
        self.assertTrue(sample.exists())

    def test_case_fts_findings_bundle_and_carving_preview(self):
        case_dir = self.root / "case"
        evidence = self.root / "payload.bin"
        evidence.write_bytes(b"prefix %PDF-1.7\n1 0 obj <<>> endobj\n%%EOF suffix")
        results = analyze_path_isolated(evidence, profile="quick")

        store_analysis_results(case_dir, results)
        finding_id = create_finding(case_dir, str(evidence), "manual finding", "detail", "low")
        update_finding(case_dir, finding_id, status="triaged", owner="analyst")
        bundle = self.root / "case.tgz"
        exported = export_case_bundle(case_dir, bundle)
        imported = import_case_bundle(bundle, self.root / "imported")

        self.assertTrue(search_fts(case_dir, "payload"))
        self.assertTrue(Path(exported["bundle"]).exists())
        self.assertTrue(Path(imported["output_dir"]).exists())
        self.assertTrue(carving_preview(evidence))

    def test_rules_artifacts_detection_and_plugin_sdk(self):
        yara = self.root / "rule.yar"
        yara.write_text("rule Demo { condition: true }", encoding="utf-8")
        sigma = self.root / "rule.yml"
        sigma.write_text("title: Demo\ndetection:\n  sel: test\ncondition: sel\n", encoding="utf-8")
        raw = self.root / "disk.dd"
        raw.write_bytes(b"\x00" * 510 + b"\x55\xaa")
        pf = self.root / "app.pf"
        pf.write_bytes((30).to_bytes(4, "little") + b"\x00" * 128)
        db = self.root / "History"
        con = sqlite3.connect(db)
        try:
            con.execute("create table urls(id integer primary key, url text)")
            con.execute("insert into urls(url) values ('https://example.com')")
            con.commit()
        finally:
            con.close()

        self.assertTrue(validate_yara_rules(yara)["valid"])
        self.assertTrue(validate_sigma_rule(sigma)["valid"])
        self.assertEqual(inspect_raw_image(raw)["sector_count_512"], 1)
        self.assertEqual(inspect_windows_artifact(pf)["type"], "prefetch")
        self.assertEqual(inspect_browser_artifact(db)["browser_hint"], "chromium")
        self.assertEqual(len(byte_histogram(yara)), 256)
        self.assertIn("00000000", virtual_hex_page(yara)["text"])
        self.assertIn("score", anomaly_score(yara))
        self.assertEqual(len(analyze_path_isolated(yara, profile="quick")), 1)
        manifest = write_example_plugin(self.root / "plugin")
        self.assertEqual(manifest["schema"], "obscuraprimus.analyzer-plugin.v1")
        plugins_root = self.root / "plugins"
        write_example_plugin(plugins_root / "demo", "demo")
        self.assertEqual(discover_plugins(plugins_root)[0].name, "demo")
        self.assertEqual(run_matching_plugins(yara, plugins_root)[0]["plugin"], "demo")

    def test_plugin_manifest_accepts_utf8_bom(self):
        plugin_dir = self.root / "bom_plugin"
        manifest = write_example_plugin(plugin_dir, "bom_demo")
        (plugin_dir / "plugin.json").write_text(
            "\ufeff" + json.dumps(manifest, indent=2),
            encoding="utf-8",
        )

        plugins = discover_plugins(plugin_dir)

        self.assertEqual(len(plugins), 1)
        self.assertEqual(plugins[0].name, "bom_demo")


if __name__ == "__main__":
    unittest.main()
