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
    assess_risk_level,
    collect_log_files,
    compute_fingerprint,
    export_csv,
    export_markdown,
    load_alert_rules,
    load_field_mapping,
    load_keyword_rules,
    match_keywords,
    normalize_message_for_fingerprint,
    parse_json_line,
    parse_log_line,
    parse_nginx_access_line,
    parse_nginx_error_line,
    parse_text_line,
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

    def test_slash_format(self):
        ts = parse_timestamp("2024/01/15 08:30:01")
        self.assertIsNotNone(ts)
        self.assertEqual(ts.year, 2024)

    def test_invalid_timestamp(self):
        ts = parse_timestamp("not a valid timestamp")
        self.assertIsNone(ts)

    def test_empty_string(self):
        ts = parse_timestamp("")
        self.assertIsNone(ts)


class TestParseTextLog(unittest.TestCase):
    def test_standard_log_line(self):
        line = "2024-01-15 08:30:01 ERROR [PaymentProcessor] Connection timeout"
        result = parse_text_line(line)
        self.assertIsNotNone(result)
        self.assertEqual(result["level"], "ERROR")
        self.assertEqual(result["module"], "PaymentProcessor")
        self.assertIn("timeout", result["message"])
        self.assertIsNotNone(result["timestamp"])

    def test_bracket_log_line(self):
        line = "[2024-01-15T12:00:00.001] [ERROR] [ApiGateway] Upstream timed out"
        result = parse_text_line(line)
        self.assertIsNotNone(result)
        self.assertEqual(result["level"], "ERROR")
        self.assertEqual(result["module"], "ApiGateway")

    def test_warning_level(self):
        line = "2024-01-15 09:05:23 WARNING [CacheManager] Cache usage at 85%"
        result = parse_text_line(line)
        self.assertIsNotNone(result)
        self.assertEqual(result["level"], "WARNING")

    def test_info_level(self):
        line = "2024-01-15 08:30:01 INFO [main] Application started"
        result = parse_text_line(line)
        self.assertIsNotNone(result)
        self.assertEqual(result["level"], "INFO")

    def test_empty_line(self):
        result = parse_text_line("")
        self.assertIsNone(result)

    def test_garbage_line(self):
        result = parse_text_line("this is not a log line")
        self.assertIsNone(result)

    def test_fatal_level(self):
        line = "2024-01-15 08:33:19 FATAL [PaymentProcessor] All retries exhausted"
        result = parse_text_line(line)
        self.assertIsNotNone(result)
        self.assertEqual(result["level"], "FATAL")

    def test_no_module(self):
        line = "2024-01-15 08:30:01 ERROR Something went wrong"
        result = parse_text_line(line)
        self.assertIsNotNone(result)
        self.assertEqual(result["module"], "UNKNOWN")


class TestParseJsonLines(unittest.TestCase):
    def test_standard_json_line(self):
        line = '{"timestamp":"2024-01-15T08:30:01","level":"ERROR","module":"Payment","message":"Connection timeout"}'
        result = parse_json_line(line)
        self.assertIsNotNone(result)
        self.assertEqual(result["level"], "ERROR")
        self.assertEqual(result["module"], "Payment")
        self.assertIn("timeout", result["message"])

    def test_alternative_field_names(self):
        line = '{"time":"2024-01-15 09:00:00","severity":"warn","service":"Auth","msg":"Failed login"}'
        result = parse_json_line(line)
        self.assertIsNotNone(result)
        self.assertEqual(result["level"], "WARN")
        self.assertEqual(result["module"], "Auth")
        self.assertIn("Failed", result["message"])

    def test_custom_field_mapping(self):
        mapping = {"timestamp": "ts", "level": "log_level", "message": "content", "module": "app"}
        line = '{"ts":"2024-01-15 10:00:00","log_level":"error","app":"OrderService","content":"NullPointerException"}'
        result = parse_json_line(line, field_mapping=mapping)
        self.assertIsNotNone(result)
        self.assertEqual(result["level"], "ERROR")
        self.assertEqual(result["module"], "OrderService")
        self.assertIn("NullPointerException", result["message"])

    def test_json_with_millis(self):
        line = '{"timestamp":"2024-01-15T08:30:01.456","level":"ERROR","message":"DB error"}'
        result = parse_json_line(line)
        self.assertIsNotNone(result)
        self.assertIsNotNone(result["timestamp"])

    def test_invalid_json(self):
        result = parse_json_line("not json at all")
        self.assertIsNone(result)

    def test_empty_json_object(self):
        result = parse_json_line("{}")
        self.assertIsNone(result)

    def test_json_array_not_object(self):
        result = parse_json_line('["a","b"]')
        self.assertIsNone(result)

    def test_missing_message_field(self):
        line = '{"timestamp":"2024-01-15T08:30:01","level":"ERROR"}'
        result = parse_json_line(line)
        self.assertIsNone(result)


class TestParseNginxLogs(unittest.TestCase):
    def test_nginx_access_500(self):
        line = '192.168.1.1 - - [15/Jan/2024:08:30:01 +0000] "POST /api/pay HTTP/1.1" 500 1024 "-" "curl/7.0"'
        result = parse_nginx_access_line(line)
        self.assertIsNotNone(result)
        self.assertEqual(result["level"], "ERROR")
        self.assertEqual(result["module"], "nginx-access")
        self.assertIn("500", result["message"])

    def test_nginx_access_404(self):
        line = '10.0.0.1 - - [15/Jan/2024:09:00:00 +0000] "GET /missing HTTP/1.1" 404 256 "-" "Mozilla/5.0"'
        result = parse_nginx_access_line(line)
        self.assertIsNotNone(result)
        self.assertEqual(result["level"], "WARNING")

    def test_nginx_access_200(self):
        line = '10.0.0.1 - - [15/Jan/2024:09:00:00 +0000] "GET /ok HTTP/1.1" 200 128 "-" "Mozilla/5.0"'
        result = parse_nginx_access_line(line)
        self.assertIsNotNone(result)
        self.assertEqual(result["level"], "INFO")

    def test_nginx_error_line(self):
        line = '2024/01/15 08:30:01 [error] 1234#5678: *9001 upstream timed out, client: 192.168.1.1, server: example.com, request: "POST /api HTTP/1.1", host: "example.com"'
        result = parse_nginx_error_line(line)
        self.assertIsNotNone(result)
        self.assertEqual(result["level"], "ERROR")
        self.assertEqual(result["module"], "nginx-error")
        self.assertIn("upstream timed out", result["message"])

    def test_nginx_error_crit_level(self):
        line = '2024/01/15 10:00:00 [crit] 1234#5678: *9002 no live upstreams, client: 10.0.0.5'
        result = parse_nginx_error_line(line)
        self.assertIsNotNone(result)
        self.assertEqual(result["level"], "CRITICAL")

    def test_nginx_error_warn_level(self):
        line = '2024/01/15 11:00:00 [warn] 1234#5678: using uninitialized variable'
        result = parse_nginx_error_line(line)
        self.assertIsNotNone(result)
        self.assertEqual(result["level"], "WARNING")

    def test_nginx_invalid_access_line(self):
        result = parse_nginx_access_line("not an nginx log")
        self.assertIsNone(result)

    def test_nginx_invalid_error_line(self):
        result = parse_nginx_error_line("not an nginx error log")
        self.assertIsNone(result)


class TestParseLogLineDispatch(unittest.TestCase):
    def test_auto_detect_json(self):
        line = '{"timestamp":"2024-01-15T08:30:01","level":"ERROR","message":"test"}'
        result = parse_log_line(line, log_format="auto")
        self.assertIsNotNone(result)
        self.assertEqual(result["level"], "ERROR")

    def test_auto_detect_text(self):
        line = "2024-01-15 08:30:01 ERROR [X] test"
        result = parse_log_line(line, log_format="auto")
        self.assertIsNotNone(result)
        self.assertEqual(result["level"], "ERROR")

    def test_force_json_format(self):
        line = '{"timestamp":"2024-01-15T08:30:01","level":"ERROR","message":"test"}'
        result = parse_log_line(line, log_format="json")
        self.assertIsNotNone(result)

    def test_force_text_format(self):
        line = "2024-01-15 08:30:01 ERROR [X] test"
        result = parse_log_line(line, log_format="text")
        self.assertIsNotNone(result)

    def test_force_nginx_error_format(self):
        line = '2024/01/15 08:30:01 [error] 1#2: something wrong'
        result = parse_log_line(line, log_format="nginx-error")
        self.assertIsNotNone(result)
        self.assertEqual(result["level"], "ERROR")

    def test_empty_line(self):
        self.assertIsNone(parse_log_line(""))
        self.assertIsNone(parse_log_line("   "))


class TestFieldMapping(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8")

    def tearDown(self):
        try:
            self.tmp.close()
        except Exception:
            pass
        try:
            os.unlink(self.tmp.name)
        except (PermissionError, OSError):
            pass

    def test_load_valid_mapping(self):
        data = {"timestamp": "ts", "level": "log_level", "message": "content", "module": "app"}
        json.dump(data, self.tmp, ensure_ascii=False)
        self.tmp.close()
        mapping = load_field_mapping(self.tmp.name)
        self.assertEqual(mapping["timestamp"], "ts")
        self.assertEqual(mapping["level"], "log_level")

    def test_mapping_missing_required(self):
        data = {"timestamp": "ts"}
        json.dump(data, self.tmp, ensure_ascii=False)
        self.tmp.close()
        with self.assertRaises(ValueError):
            load_field_mapping(self.tmp.name)

    def test_mapping_file_not_found(self):
        with self.assertRaises(FileNotFoundError):
            load_field_mapping("/nonexistent/mapping.json")

    def test_none_path_returns_none(self):
        self.assertIsNone(load_field_mapping(None))
        self.assertIsNone(load_field_mapping(""))


class TestFingerprintNormalization(unittest.TestCase):
    def test_remove_ip_address(self):
        msg = "Connection from 192.168.1.100:8080 refused"
        norm = normalize_message_for_fingerprint(msg)
        self.assertNotIn("192.168.1.100", norm)
        self.assertIn("{IP}", norm)

    def test_remove_uuid(self):
        msg = "Task 550e8400-e29b-41d4-a716-446655440000 failed"
        norm = normalize_message_for_fingerprint(msg)
        self.assertIn("{UUID}", norm)

    def test_remove_long_numbers(self):
        msg = "Order 123456789012345 processing timeout after 30000ms"
        norm = normalize_message_for_fingerprint(msg)
        self.assertIn("{LONG_ID}", norm)
        self.assertIn("{DURATION}", norm)

    def test_remove_line_number(self):
        msg = "NullPointerException at MyClass.java line 42"
        norm = normalize_message_for_fingerprint(msg)
        self.assertNotIn("42", norm)
        self.assertIn("line {NUMBER}", norm)

    def test_remove_duration(self):
        msg = "Request completed in 250ms"
        norm = normalize_message_for_fingerprint(msg)
        self.assertIn("in {DURATION}", norm)

    def test_remove_port_number(self):
        msg = "Cannot connect to port 5432"
        norm = normalize_message_for_fingerprint(msg)
        self.assertIn("port {NUMBER}", norm)

    def test_same_pattern_same_fingerprint(self):
        m1 = "User 12345 login failed from 10.0.0.1"
        m2 = "User 99999 login failed from 192.168.1.1"
        n1 = normalize_message_for_fingerprint(m1)
        n2 = normalize_message_for_fingerprint(m2)
        fp1 = compute_fingerprint("ERROR", "Auth", n1)
        fp2 = compute_fingerprint("ERROR", "Auth", n2)
        self.assertEqual(fp1, fp2)

    def test_different_module_different_fingerprint(self):
        msg = "Connection timeout"
        norm = normalize_message_for_fingerprint(msg)
        fp1 = compute_fingerprint("ERROR", "Payment", norm)
        fp2 = compute_fingerprint("ERROR", "Auth", norm)
        self.assertNotEqual(fp1, fp2)

    def test_empty_message(self):
        self.assertEqual(normalize_message_for_fingerprint(""), "")
        self.assertEqual(normalize_message_for_fingerprint(None), "")


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
        try:
            self.tmp.close()
        except Exception:
            pass
        try:
            os.unlink(self.tmp.name)
        except (PermissionError, OSError):
            pass

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


class TestAlertRules(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8")

    def tearDown(self):
        try:
            self.tmp.close()
        except Exception:
            pass
        try:
            os.unlink(self.tmp.name)
        except (PermissionError, OSError):
            pass

    def test_load_valid_alert_rules(self):
        data = {
            "alerts": [
                {"type": "keyword", "keyword": "超时", "threshold": 5, "window_minutes": 10, "risk": "HIGH"},
                {"type": "level", "level": "ERROR", "threshold": 20, "window_minutes": 60, "risk": "HIGH"},
            ]
        }
        json.dump(data, self.tmp, ensure_ascii=False)
        self.tmp.close()
        rules = load_alert_rules(self.tmp.name)
        self.assertEqual(len(rules), 2)
        self.assertEqual(rules[0]["type"], "keyword")
        self.assertEqual(rules[1]["type"], "level")

    def test_load_alerts_missing_fields(self):
        data = {"alerts": [{"type": "keyword"}]}
        json.dump(data, self.tmp, ensure_ascii=False)
        self.tmp.close()
        with self.assertRaises(ValueError):
            load_alert_rules(self.tmp.name)

    def test_load_nonexistent_file(self):
        self.assertIsNone(load_alert_rules("/nonexistent/alerts.json"))
        self.assertIsNone(load_alert_rules(None))


class TestRiskAssessment(unittest.TestCase):
    def test_critical_level(self):
        risk = assess_risk_level("CRITICAL", [], [])
        self.assertEqual(risk, "MEDIUM")

    def test_error_with_keywords(self):
        risk = assess_risk_level("ERROR", ["超时", "数据库错误"], [])
        self.assertEqual(risk, "HIGH")

    def test_error_with_alert_hits(self):
        hits = [{"reason": "test"}]
        risk = assess_risk_level("ERROR", [], hits)
        self.assertEqual(risk, "HIGH")

    def test_warning_only(self):
        risk = assess_risk_level("WARNING", [], [])
        self.assertEqual(risk, "LOW")

    def test_info_only(self):
        risk = assess_risk_level("INFO", [], [])
        self.assertEqual(risk, "INFO")


class TestCollectLogFiles(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_collect_single_log_file(self):
        log_file = os.path.join(self.test_dir, "test.log")
        Path(log_file).touch()
        files = collect_log_files(log_file)
        self.assertEqual(len(files), 1)

    def test_collect_jsonl_file(self):
        f = os.path.join(self.test_dir, "test.jsonl")
        Path(f).touch()
        files = collect_log_files(f)
        self.assertEqual(len(files), 1)

    def test_collect_json_file(self):
        f = os.path.join(self.test_dir, "data.json")
        Path(f).touch()
        files = collect_log_files(f)
        self.assertEqual(len(files), 1)

    def test_collect_single_non_log_file(self):
        txt_file = os.path.join(self.test_dir, "test.txt")
        Path(txt_file).touch()
        files = collect_log_files(txt_file)
        self.assertEqual(len(files), 1)

    def test_collect_non_supported_extension(self):
        f = os.path.join(self.test_dir, "test.csv")
        Path(f).touch()
        files = collect_log_files(f)
        self.assertEqual(len(files), 0)

    def test_collect_directory_mixed(self):
        Path(os.path.join(self.test_dir, "a.log")).touch()
        Path(os.path.join(self.test_dir, "b.jsonl")).touch()
        Path(os.path.join(self.test_dir, "c.csv")).touch()
        subdir = os.path.join(self.test_dir, "sub")
        os.mkdir(subdir)
        Path(os.path.join(subdir, "d.log")).touch()
        files = collect_log_files(self.test_dir)
        self.assertEqual(len(files), 3)


class TestAnalyzeLogsText(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.logs_dir = os.path.join(self.test_dir, "logs")
        os.mkdir(self.logs_dir)
        self.log_file = os.path.join(self.logs_dir, "app.log")
        with open(self.log_file, "w", encoding="utf-8") as f:
            f.write("2024-01-15 08:30:00 INFO [main] App started\n")
            f.write("2024-01-15 09:00:00 ERROR [Payment] Connection timeout id=123\n")
            f.write("2024-01-15 09:05:00 ERROR [Payment] Connection timeout id=456\n")
            f.write("2024-01-15 09:05:30 ERROR [Payment] Connection timeout id=9999\n")
            f.write("2024-01-15 10:00:00 WARNING [Auth] Failed login attempt from 192.168.1.10\n")
            f.write("2024-01-15 10:01:00 WARNING [Auth] Failed login attempt from 10.0.0.1\n")
            f.write("2024-01-15 10:30:00 ERROR [Order] NullPointerException at line 100\n")
            f.write("2024-01-15 10:31:00 ERROR [Order] NullPointerException at line 250\n")
            f.write("2024-01-15 11:00:00 CRITICAL [Security] SQL injection detected user_abc\n")
            f.write("2024-01-15 11:30:00 ERROR [DB] Deadlock detected timeout after 5000ms\n")

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

        self.alert_rules_file = os.path.join(self.test_dir, "alerts.json")
        alerts = {
            "alerts": [
                {"type": "keyword", "keyword": "超时", "threshold": 2, "window_minutes": 60, "risk": "HIGH"},
                {"type": "level", "level": "ERROR", "threshold": 3, "window_minutes": 60, "risk": "HIGH"},
            ]
        }
        with open(self.alert_rules_file, "w", encoding="utf-8") as f:
            json.dump(alerts, f, ensure_ascii=False)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_basic_analysis(self):
        result = analyze_logs(self.log_file)
        self.assertIsNotNone(result)
        self.assertEqual(len(result["files"]), 1)
        self.assertEqual(result["total_records"], 9)

    def test_analysis_with_rules(self):
        rules = load_keyword_rules(self.rules_file)
        result = analyze_logs(self.log_file, rules=rules)
        self.assertIsNotNone(result)
        self.assertIn("超时", result["by_keyword"])
        self.assertIn("SQL注入", result["by_keyword"])
        self.assertIn("登录失败", result["by_keyword"])

    def test_analysis_by_level(self):
        result = analyze_logs(self.log_file)
        self.assertEqual(result["by_level"].get("ERROR"), 6)
        self.assertEqual(result["by_level"].get("WARNING"), 2)
        self.assertEqual(result["by_level"].get("CRITICAL"), 1)
        self.assertNotIn("INFO", result["by_level"])

    def test_analysis_by_module(self):
        result = analyze_logs(self.log_file)
        self.assertEqual(result["by_module"].get("Payment"), 3)
        self.assertEqual(result["by_module"].get("Order"), 2)
        self.assertEqual(result["by_module"].get("Auth"), 2)

    def test_trends_granularity(self):
        result = analyze_logs(self.log_file)
        self.assertIn("by_minute", result["trends"])
        self.assertIn("by_hour", result["trends"])
        self.assertIn("by_day", result["trends"])
        self.assertIn("2024-01-15 09:00", result["trends"]["by_hour"])
        self.assertIn("2024-01-15", result["trends"]["by_day"])

    def test_fingerprints_grouping(self):
        result = analyze_logs(self.log_file)
        self.assertIn("fingerprints", result)
        self.assertIn("top_fingerprints", result)
        payment_errors = [fp for fp in result["fingerprints"] if fp["module"] == "Payment"]
        self.assertEqual(len(payment_errors), 1)
        self.assertEqual(payment_errors[0]["count"], 3)
        self.assertIn("first_seen", payment_errors[0])
        self.assertIn("last_seen", payment_errors[0])
        self.assertIn("modules", payment_errors[0])
        self.assertIn("source_files", payment_errors[0])

    def test_fingerprints_with_dynamic_ids(self):
        result = analyze_logs(self.log_file)
        auth_fp = [fp for fp in result["fingerprints"] if fp["module"] == "Auth"]
        self.assertEqual(len(auth_fp), 1)
        self.assertEqual(auth_fp[0]["count"], 2)
        order_fp = [fp for fp in result["fingerprints"] if fp["module"] == "Order"]
        self.assertEqual(len(order_fp), 1)
        self.assertEqual(order_fp[0]["count"], 2)

    def test_time_range_filter_start(self):
        start = datetime(2024, 1, 15, 10, 0, 0)
        result = analyze_logs(self.log_file, start_time=start)
        self.assertIsNotNone(result)
        self.assertEqual(result["total_records"], 6)

    def test_time_range_filter_end(self):
        end = datetime(2024, 1, 15, 9, 30, 0)
        result = analyze_logs(self.log_file, end_time=end)
        self.assertIsNotNone(result)
        self.assertEqual(result["total_records"], 3)

    def test_time_range_filter_both(self):
        start = datetime(2024, 1, 15, 9, 0, 0)
        end = datetime(2024, 1, 15, 10, 0, 0)
        result = analyze_logs(self.log_file, start_time=start, end_time=end)
        self.assertIsNotNone(result)
        self.assertEqual(result["total_records"], 4)

    def test_top_patterns(self):
        rules = load_keyword_rules(self.rules_file)
        result = analyze_logs(self.log_file, rules=rules, top_n=3)
        self.assertIsNotNone(result)
        self.assertLessEqual(len(result["top_patterns"]), 3)
        self.assertTrue(any(p["count"] >= 1 for p in result["top_patterns"]))

    def test_custom_levels(self):
        result = analyze_logs(self.log_file, levels={"ERROR"})
        self.assertIsNotNone(result)
        self.assertEqual(result["total_records"], 6)
        self.assertNotIn("WARNING", result["by_level"])
        self.assertNotIn("CRITICAL", result["by_level"])

    def test_multiple_files(self):
        log2 = os.path.join(self.logs_dir, "app2.log")
        with open(log2, "w", encoding="utf-8") as f:
            f.write("2024-01-15 12:00:00 ERROR [DB] Deadlock detected\n")
        result = analyze_logs(self.logs_dir)
        self.assertIsNotNone(result)
        self.assertEqual(len(result["files"]), 2)
        self.assertEqual(result["total_records"], 10)

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

    def test_risk_level_assigned(self):
        rules = load_keyword_rules(self.rules_file)
        result = analyze_logs(self.log_file, rules=rules)
        for rec in result["records"]:
            self.assertIn("risk", rec)
            self.assertIn(rec["risk"], {"HIGH", "MEDIUM", "LOW", "INFO"})
            self.assertIn("fingerprint", rec)

    def test_alert_rules_triggered(self):
        rules = load_keyword_rules(self.rules_file)
        alerts = load_alert_rules(self.alert_rules_file)
        result = analyze_logs(self.log_file, rules=rules, alert_rules=alerts)
        self.assertIn("high_risk_alerts", result)
        for rec in result["records"]:
            self.assertIn("alert_hits", rec)


class TestAnalyzeLogsJsonLines(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.jsonl_file = os.path.join(self.test_dir, "app.jsonl")
        with open(self.jsonl_file, "w", encoding="utf-8") as f:
            lines = [
                {"timestamp": "2024-01-15T08:30:00", "level": "INFO", "module": "main", "message": "App started"},
                {"timestamp": "2024-01-15T09:00:00", "level": "ERROR", "module": "Payment", "message": "Connection timeout id=12345"},
                {"timestamp": "2024-01-15T09:05:00", "level": "ERROR", "module": "Payment", "message": "Connection timeout id=67890"},
                {"timestamp": "2024-01-15T10:00:00", "level": "WARNING", "module": "Auth", "message": "Failed login user=u_abc"},
                {"timestamp": "2024-01-15T11:00:00", "level": "CRITICAL", "module": "Security", "message": "SQL injection detected"},
            ]
            for obj in lines:
                f.write(json.dumps(obj, ensure_ascii=False) + "\n")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_jsonl_auto_detect(self):
        result = analyze_logs(self.jsonl_file)
        self.assertIsNotNone(result)
        self.assertEqual(result["total_records"], 4)
        self.assertEqual(result["by_module"].get("Payment"), 2)

    def test_jsonl_force_format(self):
        result = analyze_logs(self.jsonl_file, log_format="json")
        self.assertIsNotNone(result)
        self.assertEqual(result["total_records"], 4)

    def test_jsonl_fingerprints(self):
        result = analyze_logs(self.jsonl_file)
        payment_fp = [fp for fp in result["fingerprints"] if "Payment" in fp["modules"]]
        self.assertEqual(len(payment_fp), 1)
        self.assertEqual(payment_fp[0]["count"], 2)


class TestAnalyzeLogsWithFieldMapping(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.jsonl_file = os.path.join(self.test_dir, "app.jsonl")
        with open(self.jsonl_file, "w", encoding="utf-8") as f:
            lines = [
                {"ts": "2024-01-15T09:00:00", "log_level": "error", "app": "PaySvc", "content": "Timeout order_id=1"},
                {"ts": "2024-01-15T09:05:00", "log_level": "error", "app": "PaySvc", "content": "Timeout order_id=2"},
                {"ts": "2024-01-15T10:00:00", "log_level": "warn", "app": "AuthSvc", "content": "Login failed"},
            ]
            for obj in lines:
                f.write(json.dumps(obj, ensure_ascii=False) + "\n")

        self.mapping_file = os.path.join(self.test_dir, "mapping.json")
        mapping = {"timestamp": "ts", "level": "log_level", "message": "content", "module": "app"}
        with open(self.mapping_file, "w", encoding="utf-8") as f:
            json.dump(mapping, f, ensure_ascii=False)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_field_mapping_applied(self):
        mapping = load_field_mapping(self.mapping_file)
        result = analyze_logs(self.jsonl_file, log_format="json", field_mapping=mapping)
        self.assertIsNotNone(result)
        self.assertEqual(result["total_records"], 3)
        self.assertEqual(result["by_module"].get("PaySvc"), 2)
        self.assertEqual(result["by_module"].get("AuthSvc"), 1)
        self.assertEqual(result["by_level"].get("ERROR"), 2)
        self.assertEqual(result["by_level"].get("WARN"), 1)

    def test_fingerprints_with_mapping(self):
        mapping = load_field_mapping(self.mapping_file)
        result = analyze_logs(self.jsonl_file, log_format="json", field_mapping=mapping)
        fp_list = result["fingerprints"]
        self.assertGreaterEqual(len(fp_list), 2)
        pay_fp = [fp for fp in fp_list if "PaySvc" in fp["modules"]]
        self.assertEqual(len(pay_fp), 1)
        self.assertEqual(pay_fp[0]["count"], 2)


class TestAnalyzeLogsNginx(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.access_log = os.path.join(self.test_dir, "access.log")
        with open(self.access_log, "w", encoding="utf-8") as f:
            f.write('192.168.1.1 - - [15/Jan/2024:08:30:01 +0000] "GET /ok HTTP/1.1" 200 128 "-" "UA"\n')
            f.write('10.0.0.1 - - [15/Jan/2024:09:00:00 +0000] "POST /api/a HTTP/1.1" 500 1024 "-" "UA"\n')
            f.write('10.0.0.2 - - [15/Jan/2024:09:05:00 +0000] "POST /api/b HTTP/1.1" 502 512 "-" "UA"\n')
            f.write('10.0.0.3 - - [15/Jan/2024:10:00:00 +0000] "GET /missing HTTP/1.1" 404 256 "-" "UA"\n')
            f.write('10.0.0.4 - - [15/Jan/2024:10:30:00 +0000] "GET /bad HTTP/1.1" 403 128 "-" "UA"\n')

        self.error_log = os.path.join(self.test_dir, "error.log")
        with open(self.error_log, "w", encoding="utf-8") as f:
            f.write('2024/01/15 09:00:00 [error] 1234#5678: *1 upstream timed out, client: 10.0.0.1\n')
            f.write('2024/01/15 09:05:00 [error] 1234#5678: *2 upstream prematurely closed, client: 10.0.0.2\n')
            f.write('2024/01/15 10:00:00 [warn] 1234#5678: *3 invalid header, client: 10.0.0.3\n')
            f.write('2024/01/15 11:00:00 [crit] 1234#5678: *4 no live upstreams while connecting\n')

    def tearDown(self):
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_nginx_access_format(self):
        result = analyze_logs(self.access_log, log_format="nginx-access")
        self.assertIsNotNone(result)
        self.assertIn("nginx-access", result["by_module"])
        self.assertEqual(result["by_level"].get("ERROR"), 2)
        self.assertEqual(result["by_level"].get("WARNING"), 2)

    def test_nginx_error_format(self):
        result = analyze_logs(self.error_log, log_format="nginx-error")
        self.assertIsNotNone(result)
        self.assertIn("nginx-error", result["by_module"])
        self.assertEqual(result["by_level"].get("ERROR"), 2)
        self.assertEqual(result["by_level"].get("WARNING"), 1)
        self.assertEqual(result["by_level"].get("CRITICAL"), 1)

    def test_nginx_auto_detect(self):
        result = analyze_logs(self.error_log)
        self.assertIsNotNone(result)
        self.assertGreater(result["total_records"], 0)

    def test_nginx_fingerprints(self):
        result = analyze_logs(self.access_log, log_format="nginx-access")
        self.assertGreaterEqual(len(result["fingerprints"]), 2)


class TestTrendsGranularity(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.log_file = os.path.join(self.test_dir, "trends.log")
        with open(self.log_file, "w", encoding="utf-8") as f:
            for day in [15, 16]:
                for hour in range(3):
                    for minute in range(0, 60, 30):
                        ts = f"2024-01-{day:02d} {hour:02d}:{minute:02d}:00"
                        f.write(f"{ts} ERROR [Mod] Error message {day}{hour}{minute}\n")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_trends_three_granularities(self):
        result = analyze_logs(self.log_file)
        trends = result["trends"]
        self.assertGreater(len(trends["by_day"]), 0)
        self.assertGreater(len(trends["by_hour"]), 0)
        self.assertGreater(len(trends["by_minute"]), 0)
        for day_key in trends["by_day"]:
            self.assertRegex(day_key, r"\d{4}-\d{2}-\d{2}$")
        for hour_key in trends["by_hour"]:
            self.assertRegex(hour_key, r"\d{4}-\d{2}-\d{2} \d{2}:00$")
        for min_key in trends["by_minute"]:
            self.assertRegex(min_key, r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}$")

    def test_counts_consistency(self):
        result = analyze_logs(self.log_file)
        day_total = sum(result["trends"]["by_day"].values())
        hour_total = sum(result["trends"]["by_hour"].values())
        min_total = sum(result["trends"]["by_minute"].values())
        self.assertEqual(day_total, hour_total)
        self.assertEqual(hour_total, min_total)
        self.assertEqual(day_total, result["total_records"])


class TestAlertThresholds(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.log_file = os.path.join(self.test_dir, "alerts.log")
        with open(self.log_file, "w", encoding="utf-8") as f:
            for i in range(6):
                ts = f"2024-01-15 09:0{i}:00"
                f.write(f"{ts} ERROR [Payment] Connection timeout in request {i}\n")
            for i in range(5):
                ts = f"2024-01-15 10:0{i}:00"
                f.write(f"{ts} ERROR [Order] DB deadlock detected id={i}\n")
            for i in range(3):
                ts = f"2024-01-15 11:0{i}:00"
                f.write(f"{ts} WARNING [Auth] Failed login attempt\n")

        self.rules_file = os.path.join(self.test_dir, "rules.json")
        rules = [
            {"name": "超时", "pattern": "timeout", "ignore_case": True},
            {"name": "登录失败", "pattern": "failed login", "ignore_case": True},
        ]
        with open(self.rules_file, "w", encoding="utf-8") as f:
            json.dump(rules, f, ensure_ascii=False)

        self.alert_rules_file = os.path.join(self.test_dir, "alerts.json")
        alert_config = {
            "alerts": [
                {"type": "keyword", "keyword": "超时", "threshold": 5, "window_minutes": 30, "risk": "HIGH"},
                {"type": "level", "level": "ERROR", "threshold": 3, "window_minutes": 60, "risk": "HIGH"},
                {"type": "keyword", "keyword": "登录失败", "threshold": 2, "window_minutes": 30, "risk": "MEDIUM"},
            ]
        }
        with open(self.alert_rules_file, "w", encoding="utf-8") as f:
            json.dump(alert_config, f, ensure_ascii=False)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_keyword_alert_triggered(self):
        rules = load_keyword_rules(self.rules_file)
        alerts = load_alert_rules(self.alert_rules_file)
        result = analyze_logs(self.log_file, rules=rules, alert_rules=alerts)
        self.assertGreater(len(result["high_risk_alerts"]), 0)

    def test_level_alert_triggered(self):
        rules = load_keyword_rules(self.rules_file)
        alerts = load_alert_rules(self.alert_rules_file)
        result = analyze_logs(self.log_file, rules=rules, alert_rules=alerts)
        level_hits = 0
        for rec in result["records"]:
            for h in rec["alert_hits"]:
                if h["rule_type"] == "level":
                    level_hits += 1
                    break
        self.assertGreater(level_hits, 0)

    def test_high_risk_records_exist(self):
        rules = load_keyword_rules(self.rules_file)
        alerts = load_alert_rules(self.alert_rules_file)
        result = analyze_logs(self.log_file, rules=rules, alert_rules=alerts)
        high_risk = [r for r in result["records"] if r["risk"] == "HIGH"]
        self.assertGreater(len(high_risk), 0)


class TestExportCSV(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.log_file = os.path.join(self.test_dir, "app.log")
        with open(self.log_file, "w", encoding="utf-8") as f:
            f.write("2024-01-15 09:00:00 ERROR [Payment] Connection timeout order_1\n")
            f.write("2024-01-15 10:00:00 WARNING [Auth] Failed login attempt\n")
            f.write("2024-01-15 11:00:00 ERROR [Payment] Connection timeout order_2\n")

        self.rules = [
            {"name": "超时", "pattern": "timeout", "ignore_case": True},
            {"name": "登录失败", "pattern": "failed login", "ignore_case": True},
        ]

    def tearDown(self):
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_export_csv_extended_fields(self):
        result = analyze_logs(self.log_file, rules=self.rules)
        out_path = os.path.join(self.test_dir, "report.csv")
        success = export_csv(result, out_path)
        self.assertTrue(success)
        self.assertTrue(os.path.exists(out_path))

        with open(out_path, "r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            fieldnames = reader.fieldnames
            self.assertIn("fingerprint", fieldnames)
            self.assertIn("risk", fieldnames)
            self.assertIn("file", fieldnames)
            self.assertIn("timestamp", fieldnames)
            self.assertIn("level", fieldnames)
            self.assertIn("module", fieldnames)
            self.assertIn("keywords", fieldnames)
            self.assertIn("message", fieldnames)
            rows = list(reader)
            self.assertEqual(len(rows), 3)
            for row in rows:
                self.assertTrue(row["fingerprint"])
                self.assertIn(row["risk"], {"HIGH", "MEDIUM", "LOW", "INFO"})
                self.assertTrue(row["file"])

    def test_export_csv_empty_records(self):
        empty_result = {
            "files": [],
            "file_counts": {},
            "total_records": 0,
            "records": [],
            "by_level": {},
            "by_module": {},
            "by_keyword": {},
            "trends": {"by_minute": {}, "by_hour": {}, "by_day": {}},
            "top_patterns": [],
            "fingerprints": [],
            "top_fingerprints": [],
            "high_risk_alerts": [],
        }
        out_path = os.path.join(self.test_dir, "empty.csv")
        success = export_csv(empty_result, out_path)
        self.assertFalse(success)
        self.assertFalse(os.path.exists(out_path))

    def test_csv_fingerprint_deduplication(self):
        result = analyze_logs(self.log_file, rules=self.rules)
        out_path = os.path.join(self.test_dir, "report.csv")
        export_csv(result, out_path)
        with open(out_path, "r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            fp_values = [row["fingerprint"] for row in reader]
        payment_fp = set()
        for rec in result["records"]:
            if rec["module"] == "Payment":
                payment_fp.add(rec["fingerprint"])
        self.assertEqual(len(payment_fp), 1)


class TestExportMarkdown(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.log_file = os.path.join(self.test_dir, "app.log")
        with open(self.log_file, "w", encoding="utf-8") as f:
            f.write("2024-01-15 09:00:00 ERROR [Payment] Connection timeout order_1\n")
            f.write("2024-01-15 09:05:00 ERROR [Payment] Connection timeout order_2\n")
            f.write("2024-01-15 10:00:00 WARNING [Auth] Failed login attempt\n")
            f.write("2024-01-15 11:00:00 CRITICAL [Security] SQL injection\n")

        self.rules = [
            {"name": "超时", "pattern": "timeout", "ignore_case": True},
            {"name": "SQL注入", "pattern": "SQL injection", "ignore_case": True},
        ]
        self.alert_file = os.path.join(self.test_dir, "alerts.json")
        with open(self.alert_file, "w", encoding="utf-8") as f:
            json.dump({"alerts": [
                {"type": "keyword", "keyword": "超时", "threshold": 2, "window_minutes": 60, "risk": "HIGH"}
            ]}, f, ensure_ascii=False)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_export_markdown_complete(self):
        rules = self.rules
        alerts = load_alert_rules(self.alert_file)
        result = analyze_logs(self.log_file, rules=rules, alert_rules=alerts)
        out_path = os.path.join(self.test_dir, "report.md")
        success = export_markdown(result, out_path, top_n=10)
        self.assertTrue(success)
        self.assertTrue(os.path.exists(out_path))

        with open(out_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("# 日志异常模式分析报告", content)
        self.assertIn("## 总体概览", content)
        self.assertIn("## 级别统计", content)
        self.assertIn("## 模块统计", content)
        self.assertIn("## 关键字命中", content)
        self.assertIn("异常指纹", content)
        self.assertIn("## 时间趋势", content)
        self.assertIn("按天统计", content)
        self.assertIn("按小时统计", content)
        self.assertIn("按分钟统计", content)

    def test_markdown_has_tables(self):
        result = analyze_logs(self.log_file, rules=self.rules)
        out_path = os.path.join(self.test_dir, "report.md")
        export_markdown(result, out_path)
        with open(out_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("| 指标 | 数值 |", content)
        self.assertIn("| 级别 | 次数 | 占比 |", content)

    def test_markdown_contains_high_risk_alerts(self):
        rules = self.rules
        alerts = load_alert_rules(self.alert_file)
        result = analyze_logs(self.log_file, rules=rules, alert_rules=alerts)
        out_path = os.path.join(self.test_dir, "report.md")
        export_markdown(result, out_path)
        with open(out_path, "r", encoding="utf-8") as f:
            content = f.read()
        if result["high_risk_alerts"]:
            self.assertIn("高风险告警列表", content)


class TestAbnormalInputs(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_mixed_valid_and_invalid_lines(self):
        log_file = os.path.join(self.test_dir, "mixed.log")
        with open(log_file, "w", encoding="utf-8") as f:
            f.write("2024-01-15 09:00:00 ERROR [Mod] Valid error\n")
            f.write("some random garbage line\n")
            f.write("\n")
            f.write("   \n")
            f.write("2024-01-15 10:00:00 WARNING [Mod] Valid warning\n")
            f.write("NOT A LOG FORMAT\n")
        result = analyze_logs(log_file)
        self.assertIsNotNone(result)
        self.assertEqual(result["total_records"], 2)

    def test_corrupted_json_lines(self):
        jsonl = os.path.join(self.test_dir, "bad.jsonl")
        with open(jsonl, "w", encoding="utf-8") as f:
            f.write('{"timestamp":"2024-01-15T09:00:00","level":"ERROR","message":"ok"}\n')
            f.write('not json at all\n')
            f.write('{"timestamp":"2024-01-15T10:00:00","level":"WARN","message":"warn"}\n')
            f.write('{"broken json: 123\n')
            f.write('[]\n')
        result = analyze_logs(jsonl, log_format="json")
        self.assertIsNotNone(result)
        self.assertEqual(result["total_records"], 2)

    def test_empty_log_file(self):
        log_file = os.path.join(self.test_dir, "empty.log")
        open(log_file, "w").close()
        result = analyze_logs(log_file)
        self.assertIsNotNone(result)
        self.assertEqual(result["total_records"], 0)

    def test_non_utf8_file(self):
        log_file = os.path.join(self.test_dir, "encoding.log")
        with open(log_file, "wb") as f:
            f.write(b"2024-01-15 09:00:00 ERROR [Mod] Error \xff\xfe message\n")
            f.write(b"2024-01-15 10:00:00 ERROR [Mod] Normal error\n")
        result = analyze_logs(log_file)
        self.assertIsNotNone(result)
        self.assertGreaterEqual(result["total_records"], 1)

    def test_very_long_line(self):
        log_file = os.path.join(self.test_dir, "long.log")
        with open(log_file, "w", encoding="utf-8") as f:
            long_msg = "X" * 10000
            f.write(f"2024-01-15 09:00:00 ERROR [Mod] {long_msg}\n")
        result = analyze_logs(log_file)
        self.assertIsNotNone(result)
        self.assertEqual(result["total_records"], 1)

    def test_timestamps_without_time(self):
        log_file = os.path.join(self.test_dir, "notime.log")
        with open(log_file, "w", encoding="utf-8") as f:
            f.write("ERROR [Mod] No timestamp at all\n")
            f.write("2024-01-15 09:00:00 ERROR [Mod] With timestamp\n")
        result = analyze_logs(log_file)
        self.assertIsNotNone(result)
        self.assertEqual(result["total_records"], 1)

    def test_nonexistent_path_in_analyze(self):
        result = analyze_logs("/nonexistent/path/that/never/existed.log")
        self.assertIsNone(result)


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

        self.base = os.path.dirname(os.path.abspath(__file__))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _run(self, args):
        import subprocess
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        return subprocess.run(
            [sys.executable, "log_analyzer.py", *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            cwd=self.base,
        )

    def test_cli_basic_run(self):
        result = self._run([self.log_file])
        self.assertEqual(result.returncode, 0)
        self.assertIn("异常记录总数", result.stdout)
        self.assertIn("ERROR", result.stdout)

    def test_cli_with_rules(self):
        result = self._run([self.log_file, "-r", self.rules_file])
        self.assertEqual(result.returncode, 0)
        self.assertIn("关键字规则统计", result.stdout)

    def test_cli_json_output(self):
        result = self._run([self.log_file, "--json"])
        self.assertEqual(result.returncode, 0)
        data = json.loads(result.stdout)
        self.assertIn("total_records", data)
        self.assertIn("by_level", data)
        self.assertIn("trends", data)
        self.assertIn("top_fingerprints", data)

    def test_cli_csv_export(self):
        out_path = os.path.join(self.test_dir, "output.csv")
        result = self._run([self.log_file, "-o", out_path])
        self.assertEqual(result.returncode, 0)
        self.assertTrue(os.path.exists(out_path))

    def test_cli_markdown_export(self):
        md_path = os.path.join(self.test_dir, "report.md")
        result = self._run([self.log_file, "--markdown", md_path])
        self.assertEqual(result.returncode, 0)
        self.assertTrue(os.path.exists(md_path))
        with open(md_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("# 日志异常模式分析报告", content)

    def test_cli_csv_and_markdown_together(self):
        out_csv = os.path.join(self.test_dir, "out.csv")
        out_md = os.path.join(self.test_dir, "out.md")
        result = self._run([self.log_file, "-o", out_csv, "--markdown", out_md])
        self.assertEqual(result.returncode, 0)
        self.assertTrue(os.path.exists(out_csv))
        self.assertTrue(os.path.exists(out_md))

    def test_cli_time_filter(self):
        result = self._run([
            self.log_file,
            "--start", "2024-01-15 09:30:00",
            "--end", "2024-01-15 11:00:00",
        ])
        self.assertEqual(result.returncode, 0)

    def test_cli_invalid_path(self):
        result = self._run(["/nonexistent"])
        self.assertNotEqual(result.returncode, 0)

    def test_cli_top_n(self):
        result = self._run([self.log_file, "--top", "5"])
        self.assertEqual(result.returncode, 0)
        self.assertIn("Top 5", result.stdout)

    def test_cli_format_json_flag(self):
        jsonl = os.path.join(self.test_dir, "app.jsonl")
        with open(jsonl, "w", encoding="utf-8") as f:
            f.write('{"timestamp":"2024-01-15T09:00:00","level":"ERROR","message":"Test error"}\n')
        result = self._run([jsonl, "--format", "json", "--json"])
        self.assertEqual(result.returncode, 0)
        data = json.loads(result.stdout)
        self.assertEqual(data["total_records"], 1)

    def test_cli_mapping_flag(self):
        jsonl = os.path.join(self.test_dir, "custom.jsonl")
        with open(jsonl, "w", encoding="utf-8") as f:
            f.write('{"ts":"2024-01-15 09:00:00","log_level":"error","content":"DB error"}\n')
        mapping = os.path.join(self.test_dir, "mapping.json")
        with open(mapping, "w", encoding="utf-8") as f:
            json.dump({"timestamp": "ts", "level": "log_level", "message": "content"}, f)
        result = self._run([jsonl, "--format", "json", "--mapping", mapping, "--json"])
        self.assertEqual(result.returncode, 0)
        data = json.loads(result.stdout)
        self.assertEqual(data["total_records"], 1)

    def test_cli_alert_rules_flag(self):
        alert_file = os.path.join(self.test_dir, "alerts.json")
        with open(alert_file, "w", encoding="utf-8") as f:
            json.dump({"alerts": [
                {"type": "keyword", "keyword": "超时", "threshold": 1, "window_minutes": 60, "risk": "HIGH"}
            ]}, f, ensure_ascii=False)
        result = self._run([self.log_file, "-r", self.rules_file, "--alert-rules", alert_file, "--json"])
        self.assertEqual(result.returncode, 0)
        data = json.loads(result.stdout)
        self.assertIn("high_risk_alerts", data)


def run_tests():
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(run_tests())
