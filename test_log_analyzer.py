#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import csv
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from log_analyzer import (
    ABNORMAL_LEVELS,
    analyze_logs,
    collect_log_files,
    export_csv,
    load_keyword_rules,
    match_keywords,
    parse_log_line,
    parse_timestamp,
)


class TestParseTimestamp(unittest.TestCase):
    def test_standard_format(self):
        ts = parse_timestamp("2024-01-15 08:30:01")
        self.assertIsNotNone(ts)
        self.assertEqual(ts.year, 2024)
        self.assertEqual(ts.month, 1)
        self.assertEqual(ts.day, 15)
        self.assertEqual(ts.hour, 8)

    def test_iso_format_with_millis(self):
        ts = parse_timestamp("2024-01-15T08:30:01.123")
        self.assertIsNotNone(ts)
        self.assertEqual(ts.hour, 8)
        self.assertEqual(ts.minute, 30)

    def test_iso_format_comma_millis(self):
        ts = parse_timestamp("2024-01-15T08:30:01,123")
        self.assertIsNotNone(ts)

    def test_invalid_timestamp(self):
        ts = parse_timestamp("not a valid timestamp")
        self.assertIsNone(ts)

    def test_empty_string(self):
        ts = parse_timestamp("")
        self.assertIsNone(ts)


class TestParseLogLine(unittest.TestCase):
    def test_standard_log_line(self):
        line = "2024-01-15 08:30:01 ERROR [PaymentProcessor] Connection timeout"
        result = parse_log_line(line)
        self.assertIsNotNone(result)
        self.assertEqual(result["level"], "ERROR")
        self.assertEqual(result["module"], "PaymentProcessor")
        self.assertIn("timeout", result["message"])
        self.assertIsNotNone(result["timestamp"])

    def test_bracket_log_line(self):
        line = "[2024-01-15T12:00:00.001] [ERROR] [ApiGateway] Upstream timed out"
        result = parse_log_line(line)
        self.assertIsNotNone(result)
        self.assertEqual(result["level"], "ERROR")
        self.assertEqual(result["module"], "ApiGateway")

    def test_warning_level(self):
        line = "2024-01-15 09:05:23 WARNING [CacheManager] Cache usage at 85%"
        result = parse_log_line(line)
        self.assertIsNotNone(result)
        self.assertEqual(result["level"], "WARNING")

    def test_info_level_skipped_by_filter(self):
        line = "2024-01-15 08:30:01 INFO [main] Application started"
        result = parse_log_line(line)
        self.assertIsNotNone(result)
        self.assertEqual(result["level"], "INFO")

    def test_empty_line(self):
        result = parse_log_line("")
        self.assertIsNone(result)

    def test_garbage_line(self):
        result = parse_log_line("this is not a log line")
        self.assertIsNone(result)

    def test_fatal_level(self):
        line = "2024-01-15 08:33:19 FATAL [PaymentProcessor] All retries exhausted"
        result = parse_log_line(line)
        self.assertIsNotNone(result)
        self.assertEqual(result["level"], "FATAL")

    def test_no_module(self):
        line = "2024-01-15 08:30:01 ERROR Something went wrong"
        result = parse_log_line(line)
        self.assertIsNotNone(result)
        self.assertEqual(result["module"], "UNKNOWN")


class TestKeywordRules(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8")
        self.rules_data = [
            {"name": "超时错误", "pattern": "timeout", "ignore_case": True},
            {"name": "数据库错误", "pattern": "deadlock|exhausted", "ignore_case": True},
        ]
        json.dump(self.rules_data, self.tmp, ensure_ascii=False)
        self.tmp.close()

    def tearDown(self):
        os.unlink(self.tmp.name)

    def test_load_valid_rules(self):
        rules = load_keyword_rules(self.tmp.name)
        self.assertEqual(len(rules), 2)
        self.assertEqual(rules[0]["name"], "超时错误")

    def test_load_nonexistent_file(self):
        rules = load_keyword_rules("/nonexistent/path/rules.json")
        self.assertEqual(rules, [])

    def test_load_invalid_json(self):
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8")
        tmp.write("not valid json {{{")
        tmp.close()
        try:
            with self.assertRaises(json.JSONDecodeError):
                load_keyword_rules(tmp.name)
        finally:
            os.unlink(tmp.name)

    def test_load_invalid_format(self):
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8")
        json.dump({"not": "a list"}, tmp)
        tmp.close()
        try:
            with self.assertRaises(ValueError):
                load_keyword_rules(tmp.name)
        finally:
            os.unlink(tmp.name)

    def test_load_missing_fields(self):
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8")
        json.dump([{"name": "no pattern"}], tmp)
        tmp.close()
        try:
            with self.assertRaises(ValueError):
                load_keyword_rules(tmp.name)
        finally:
            os.unlink(tmp.name)

    def test_match_keywords(self):
        rules = [
            {"name": "超时", "pattern": "timeout", "ignore_case": True},
            {"name": "空指针", "pattern": "NullPointerException", "ignore_case": False},
        ]
        matches = match_keywords("Connection timeout when calling gateway", rules)
        self.assertIn("超时", matches)

    def test_match_keywords_case_sensitive(self):
        rules = [{"name": "空指针", "pattern": "NullPointerException", "ignore_case": False}]
        matches = match_keywords("nullpointerexception lowercase", rules)
        self.assertEqual(matches, [])

    def test_match_keywords_case_insensitive(self):
        rules = [{"name": "超时", "pattern": "TIMEOUT", "ignore_case": True}]
        matches = match_keywords("connection timeout occurred", rules)
        self.assertIn("超时", matches)

    def test_match_keywords_no_match(self):
        rules = [{"name": "超时", "pattern": "timeout"}]
        matches = match_keywords("everything is fine", rules)
        self.assertEqual(matches, [])

    def test_match_keywords_invalid_regex(self):
        rules = [{"name": "坏正则", "pattern": "[invalid", "ignore_case": True}]
        matches = match_keywords("some message", rules)
        self.assertEqual(matches, [])


class TestCollectLogFiles(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_collect_single_file(self):
        log_file = os.path.join(self.test_dir, "test.log")
        Path(log_file).touch()
        files = collect_log_files(log_file)
        self.assertEqual(len(files), 1)

    def test_collect_single_non_log_file(self):
        txt_file = os.path.join(self.test_dir, "test.txt")
        Path(txt_file).touch()
        files = collect_log_files(txt_file)
        self.assertEqual(len(files), 0)

    def test_collect_directory(self):
        Path(os.path.join(self.test_dir, "a.log")).touch()
        Path(os.path.join(self.test_dir, "b.log")).touch()
        Path(os.path.join(self.test_dir, "c.txt")).touch()
        subdir = os.path.join(self.test_dir, "sub")
        os.mkdir(subdir)
        Path(os.path.join(subdir, "d.log")).touch()
        files = collect_log_files(self.test_dir)
        self.assertEqual(len(files), 3)


class TestAnalyzeLogs(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.log_file = os.path.join(self.test_dir, "app.log")
        with open(self.log_file, "w", encoding="utf-8") as f:
            f.write("2024-01-15 08:30:00 INFO [main] App started\n")
            f.write("2024-01-15 09:00:00 ERROR [Payment] Connection timeout in payment\n")
            f.write("2024-01-15 09:05:00 ERROR [Payment] Connection timeout again\n")
            f.write("2024-01-15 10:00:00 WARNING [Auth] Failed login attempt\n")
            f.write("2024-01-15 10:30:00 ERROR [Order] NullPointerException at line 100\n")
            f.write("2024-01-15 11:00:00 CRITICAL [Security] SQL injection detected\n")

        self.rules_file = os.path.join(self.test_dir, "rules.json")
        rules = [
            {"name": "超时", "pattern": "timeout", "ignore_case": True},
            {"name": "登录失败", "pattern": "failed login", "ignore_case": True},
            {"name": "空指针", "pattern": "NullPointerException", "ignore_case": False},
            {"name": "SQL注入", "pattern": "SQL injection", "ignore_case": True},
            {"name": "支付相关", "pattern": "payment", "ignore_case": True},
        ]
        with open(self.rules_file, "w", encoding="utf-8") as f:
            json.dump(rules, f, ensure_ascii=False)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_basic_analysis(self):
        result = analyze_logs(self.log_file)
        self.assertIsNotNone(result)
        self.assertEqual(len(result["files"]), 1)
        self.assertEqual(result["total_records"], 5)

    def test_analysis_with_rules(self):
        rules = load_keyword_rules(self.rules_file)
        result = analyze_logs(self.log_file, rules=rules)
        self.assertIsNotNone(result)
        self.assertIn("超时", result["by_keyword"])
        self.assertIn("SQL注入", result["by_keyword"])

    def test_analysis_by_level(self):
        result = analyze_logs(self.log_file)
        self.assertEqual(result["by_level"].get("ERROR"), 3)
        self.assertEqual(result["by_level"].get("WARNING"), 1)
        self.assertEqual(result["by_level"].get("CRITICAL"), 1)
        self.assertNotIn("INFO", result["by_level"])

    def test_analysis_by_module(self):
        result = analyze_logs(self.log_file)
        self.assertEqual(result["by_module"].get("Payment"), 2)
        self.assertEqual(result["by_module"].get("Order"), 1)

    def test_analysis_by_hour(self):
        result = analyze_logs(self.log_file)
        self.assertIn("2024-01-15 09:00", result["by_hour"])
        self.assertEqual(result["by_hour"]["2024-01-15 09:00"], 2)

    def test_time_range_filter_start(self):
        start = datetime(2024, 1, 15, 10, 0, 0)
        result = analyze_logs(self.log_file, start_time=start)
        self.assertIsNotNone(result)
        self.assertEqual(result["total_records"], 3)

    def test_time_range_filter_end(self):
        end = datetime(2024, 1, 15, 9, 30, 0)
        result = analyze_logs(self.log_file, end_time=end)
        self.assertIsNotNone(result)
        self.assertEqual(result["total_records"], 2)

    def test_time_range_filter_both(self):
        start = datetime(2024, 1, 15, 9, 0, 0)
        end = datetime(2024, 1, 15, 10, 0, 0)
        result = analyze_logs(self.log_file, start_time=start, end_time=end)
        self.assertIsNotNone(result)
        self.assertEqual(result["total_records"], 3)

    def test_top_patterns(self):
        rules = load_keyword_rules(self.rules_file)
        result = analyze_logs(self.log_file, rules=rules, top_n=3)
        self.assertIsNotNone(result)
        self.assertLessEqual(len(result["top_patterns"]), 3)
        self.assertTrue(any(p["count"] >= 1 for p in result["top_patterns"]))

    def test_custom_levels(self):
        result = analyze_logs(self.log_file, levels={"ERROR"})
        self.assertIsNotNone(result)
        self.assertEqual(result["total_records"], 3)
        self.assertNotIn("WARNING", result["by_level"])
        self.assertNotIn("CRITICAL", result["by_level"])

    def test_multiple_files(self):
        log2 = os.path.join(self.test_dir, "app2.log")
        with open(log2, "w", encoding="utf-8") as f:
            f.write("2024-01-15 12:00:00 ERROR [DB] Deadlock detected\n")
        result = analyze_logs(self.test_dir)
        self.assertIsNotNone(result)
        self.assertEqual(len(result["files"]), 2)
        self.assertEqual(result["total_records"], 6)

    def test_no_log_files(self):
        empty_dir = tempfile.mkdtemp()
        try:
            result = analyze_logs(empty_dir)
            self.assertIsNone(result)
        finally:
            import shutil
            shutil.rmtree(empty_dir, ignore_errors=True)

    def test_nonexistent_path(self):
        result = analyze_logs("/nonexistent/path")
        self.assertIsNone(result)


class TestExportCSV(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.log_file = os.path.join(self.test_dir, "app.log")
        with open(self.log_file, "w", encoding="utf-8") as f:
            f.write("2024-01-15 09:00:00 ERROR [Payment] Connection timeout\n")
            f.write("2024-01-15 10:00:00 WARNING [Auth] Failed login\n")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_export_csv_success(self):
        rules = [
            {"name": "超时", "pattern": "timeout", "ignore_case": True},
            {"name": "登录失败", "pattern": "failed login", "ignore_case": True},
        ]
        result = analyze_logs(self.log_file, rules=rules)
        out_path = os.path.join(self.test_dir, "report.csv")
        success = export_csv(result, out_path)
        self.assertTrue(success)
        self.assertTrue(os.path.exists(out_path))

        with open(out_path, "r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            self.assertEqual(len(rows), 2)
            self.assertIn("level", rows[0])
            self.assertIn("message", rows[0])
            self.assertEqual(rows[0]["level"], "ERROR")

    def test_export_csv_empty_records(self):
        empty_result = {
            "files": [],
            "total_records": 0,
            "records": [],
            "by_level": {},
            "by_module": {},
            "by_keyword": {},
            "by_hour": {},
            "top_patterns": [],
        }
        out_path = os.path.join(self.test_dir, "empty.csv")
        success = export_csv(empty_result, out_path)
        self.assertFalse(success)
        self.assertFalse(os.path.exists(out_path))


class TestIntegrationCLI(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.log_file = os.path.join(self.test_dir, "app.log")
        with open(self.log_file, "w", encoding="utf-8") as f:
            f.write("2024-01-15 08:30:00 INFO [main] App started\n")
            f.write("2024-01-15 09:00:00 ERROR [Payment] Connection timeout\n")
            f.write("2024-01-15 10:00:00 WARNING [Auth] Failed login attempt\n")

        self.rules_file = os.path.join(self.test_dir, "rules.json")
        rules = [
            {"name": "超时", "pattern": "timeout", "ignore_case": True},
            {"name": "登录失败", "pattern": "failed login", "ignore_case": True},
        ]
        with open(self.rules_file, "w", encoding="utf-8") as f:
            json.dump(rules, f, ensure_ascii=False)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_cli_basic_run(self):
        import subprocess
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        result = subprocess.run(
            [sys.executable, "log_analyzer.py", self.log_file],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            cwd=os.path.dirname(os.path.abspath(__file__)),
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("异常记录总数", result.stdout)
        self.assertIn("ERROR", result.stdout)

    def test_cli_with_rules(self):
        import subprocess
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        result = subprocess.run(
            [sys.executable, "log_analyzer.py", self.log_file, "-r", self.rules_file],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            cwd=os.path.dirname(os.path.abspath(__file__)),
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("关键字规则统计", result.stdout)

    def test_cli_json_output(self):
        import subprocess
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        result = subprocess.run(
            [sys.executable, "log_analyzer.py", self.log_file, "--json"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            cwd=os.path.dirname(os.path.abspath(__file__)),
        )
        self.assertEqual(result.returncode, 0)
        data = json.loads(result.stdout)
        self.assertIn("total_records", data)
        self.assertIn("by_level", data)

    def test_cli_csv_export(self):
        import subprocess
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        out_path = os.path.join(self.test_dir, "output.csv")
        result = subprocess.run(
            [sys.executable, "log_analyzer.py", self.log_file, "-o", out_path],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            cwd=os.path.dirname(os.path.abspath(__file__)),
        )
        self.assertEqual(result.returncode, 0)
        self.assertTrue(os.path.exists(out_path))

    def test_cli_time_filter(self):
        import subprocess
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        result = subprocess.run(
            [
                sys.executable, "log_analyzer.py", self.log_file,
                "--start", "2024-01-15 09:30:00",
                "--end", "2024-01-15 11:00:00",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            cwd=os.path.dirname(os.path.abspath(__file__)),
        )
        self.assertEqual(result.returncode, 0)

    def test_cli_invalid_path(self):
        import subprocess
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        result = subprocess.run(
            [sys.executable, "log_analyzer.py", "/nonexistent"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            cwd=os.path.dirname(os.path.abspath(__file__)),
        )
        self.assertNotEqual(result.returncode, 0)

    def test_cli_top_n(self):
        import subprocess
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        result = subprocess.run(
            [sys.executable, "log_analyzer.py", self.log_file, "--top", "5"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            cwd=os.path.dirname(os.path.abspath(__file__)),
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("Top 5", result.stdout)


def run_tests():
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(run_tests())
