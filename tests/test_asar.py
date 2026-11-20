#!/usr/bin/env python3
"""Автотесты для нативного бэкенда far2l-asar."""
import hashlib
import json
import os
import stat
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

BIN = Path(__file__).resolve().parent.parent / "far2l-asar"


def read_asar_header(asar_path: Path) -> dict:
    data = asar_path.read_bytes()
    magic, header_size, payload_size, json_size = struct.unpack("<4I", data[:16])
    assert magic == 4
    assert payload_size + 4 == header_size
    assert payload_size % 4 == 0
    return json.loads(data[16 : 16 + json_size].decode("utf-8"))


class TestFar2lAsar(unittest.TestCase):
    def setUp(self):
        self.assertTrue(BIN.exists(), f"Бинарник не найден: {BIN}. Сначала выполните make.")
        self.tmp = tempfile.TemporaryDirectory(prefix="test-far2l-asar-")
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def run_bin(self, *args, cwd=None, expect_ok=True):
        res = subprocess.run(
            [str(BIN), *map(str, args)],
            cwd=cwd or self.root,
            capture_output=True,
            text=True,
        )
        if expect_ok and res.returncode != 0:
            self.fail(f"Команда завершилась с кодом {res.returncode}:\nSTDERR: {res.stderr}\nSTDOUT: {res.stdout}")
        if not expect_ok and res.returncode == 0:
            self.fail(f"Ожидалась ошибка, но команда завершилась успешно: {args}")
        return res

    def make_list_file(self, items: list[str]) -> Path:
        lst = self.root / f"list-{os.urandom(4).hex()}.txt"
        lst.write_text("\n".join(items) + "\n", encoding="utf-8")
        return lst

    def test_01_create_list_extract_and_integrity(self):
        src = self.root / "src"
        (src / "папка с пробелом").mkdir(parents=True)
        (src / "empty.txt").write_bytes(b"")
        (src / "папка с пробелом" / "привет.txt").write_text("Тест кириллицы\n", encoding="utf-8")

        script = src / "run.sh"
        script.write_text("#!/bin/sh\necho ok\n", encoding="utf-8")
        script.chmod(0o755)

        big_data = os.urandom(5 * 1024 * 1024 + 123)
        (src / "big.bin").write_bytes(big_data)

        asar = self.root / "app.asar"
        lst = self.make_list_file(["empty.txt", "папка с пробелом", "run.sh", "big.bin"])
        self.run_bin("add", asar, "--list", lst, cwd=src)

        hdr = read_asar_header(asar)
        big_meta = hdr["files"]["big.bin"]
        self.assertEqual(big_meta["size"], len(big_data))
        self.assertEqual(big_meta["integrity"]["hash"], hashlib.sha256(big_data).hexdigest())
        self.assertEqual(len(big_meta["integrity"]["blocks"]), 2)
        self.assertTrue(hdr["files"]["run.sh"].get("executable"))

        out_list = self.run_bin("list", asar).stdout.splitlines()
        self.assertTrue(any("D 00000000000000000000 папка с пробелом" in line for line in out_list))
        self.assertTrue(any(". 00000000000000000000 empty.txt" in line for line in out_list))

        out_dir = self.root / "extracted"
        out_dir.mkdir()
        self.run_bin("extract", asar, "--list", self.make_list_file(["*"]), cwd=out_dir)

        self.assertEqual((out_dir / "big.bin").read_bytes(), big_data)
        self.assertEqual((out_dir / "папка с пробелом" / "привет.txt").read_text("utf-8"), "Тест кириллицы\n")
        self.assertTrue((out_dir / "run.sh").stat().st_mode & stat.S_IXUSR)

    def test_02_replace_file_with_different_size(self):
        src = self.root / "src"
        src.mkdir()
        (src / "a_first.txt").write_bytes(b"SHORT")
        (src / "b_second.txt").write_bytes(b"SECOND_FILE_CONTENT_12345")

        asar = self.root / "replace.asar"
        self.run_bin("add", asar, "--list", self.make_list_file(["a_first.txt", "b_second.txt"]), cwd=src)

        new_first = b"LONG_REPLACED_CONTENT_" * 500
        (src / "a_first.txt").write_bytes(new_first)
        self.run_bin("add", asar, "--list", self.make_list_file(["a_first.txt"]), cwd=src)

        out_dir = self.root / "out"
        out_dir.mkdir()
        self.run_bin("extract", asar, "--list", self.make_list_file(["*"]), cwd=out_dir)

        self.assertEqual((out_dir / "a_first.txt").read_bytes(), new_first)
        self.assertEqual((out_dir / "b_second.txt").read_bytes(), b"SECOND_FILE_CONTENT_12345")
        baks = list(self.root.glob("replace.asar.bak-*"))
        self.assertEqual(baks, [], f"Найдены неудалённые бэкапы: {baks}")

    def test_03_root_and_flat_extract(self):
        src = self.root / "src"
        (src / "sub" / "nested").mkdir(parents=True)
        (src / "sub" / "nested" / "deep.txt").write_text("deep", encoding="utf-8")

        asar = self.root / "sub.asar"
        self.run_bin("add", asar, "--list", self.make_list_file(["sub"]), cwd=src)

        out_dir = self.root / "flat_out"
        out_dir.mkdir()
        self.run_bin("extract", asar, "--list", self.make_list_file(["sub/nested"]), "--root", "sub", "--flat", cwd=out_dir)
        self.assertEqual((out_dir / "deep.txt").read_text("utf-8"), "deep")

    def test_04_unpacked_preservation(self):
        asar = self.root / "ext.asar"
        unpacked_dir = self.root / "ext.asar.unpacked"
        unpacked_dir.mkdir()
        (unpacked_dir / "native.node").write_bytes(b"OLD_BINARY")

        header_obj = {
            "files": {
                "native.node": {"size": 10, "unpacked": True},
                "index.js": {"size": 4, "offset": "0"},
            }
        }
        raw_json = json.dumps(header_obj, separators=(",", ":")).encode("utf-8")
        payload_size = (4 + len(raw_json) + 3) & ~3
        header_size = payload_size + 4
        preamble = struct.pack("<4I", 4, header_size, payload_size, len(raw_json))
        pad = b"\x00" * (payload_size - 4 - len(raw_json))
        asar.write_bytes(preamble + raw_json + pad + b"CODE")

        src = self.root / "upd"
        src.mkdir()
        (src / "native.node").write_bytes(b"NEW_BINARY_DATA")
        self.run_bin("add", asar, "--list", self.make_list_file(["native.node"]), cwd=src)

        hdr = read_asar_header(asar)
        self.assertTrue(hdr["files"]["native.node"].get("unpacked"))
        self.assertEqual((unpacked_dir / "native.node").read_bytes(), b"NEW_BINARY_DATA")

    def test_05_security_checks(self):
        src = self.root / "sec"
        (src / "dir").mkdir(parents=True)
        (src / "dir" / "f.txt").write_text("1", encoding="utf-8")
        asar = self.root / "sec.asar"
        self.run_bin("add", asar, "--list", self.make_list_file(["dir"]), cwd=src)

        (src / "dir_as_file").write_text("2", encoding="utf-8")
        (src / "dir").rename(src / "dir_backup")
        (src / "dir_as_file").rename(src / "dir")
        self.run_bin("add", asar, "--list", self.make_list_file(["dir"]), cwd=src, expect_ok=False)

        bad_list = self.make_list_file(["../evil.txt"])
        self.run_bin("extract", asar, "--list", bad_list, expect_ok=False)

    def test_06_concurrent_flock_writes(self):
        src = self.root / "conc"
        src.mkdir()
        for idx in range(6):
            (src / f"file_{idx}.txt").write_text(f"payload_{idx}", encoding="utf-8")

        asar = self.root / "concurrent.asar"
        procs = []
        for idx in range(6):
            lst = self.make_list_file([f"file_{idx}.txt"])
            p = subprocess.Popen(
                [str(BIN), "add", str(asar), "--list", str(lst)],
                cwd=src,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            procs.append(p)

        for p in procs:
            _, err = p.communicate(timeout=15)
            self.assertEqual(p.returncode, 0, f"Сбой при параллельной записи: {err}")

        hdr = read_asar_header(asar)
        for idx in range(6):
            self.assertIn(f"file_{idx}.txt", hdr["files"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
