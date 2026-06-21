#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import csv
import hashlib
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path


TEXT_LOG_PATTERNS = [
    re.compile(
        r'(?P<timestamp>\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)'
        r'\s+'
        r'(?P<level>DEBUG|INFO|WARNING|WARN|ERROR|FATAL|CRITICAL|TRACE)'
        r'\s+'
        r'(?:\[(?P<module>[^\]]+)\])?'
        r'\s*'
        r'(?P<message>.*)'
    ),
    re.compile(
        r'\[(?P<timestamp>\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)\]'
        r'\s+'
        r'\[(?P<level>DEBUG|INFO|WARNING|WARN|ERROR|FATAL|CRITICAL|TRACE)\]'
        r'\s+'
        r'(?:\[(?P<module>[^\]]+)\])?'
        r'\s*'
        r'(?P<message>.*)'
    ),
]

NGINX_ACCESS_PATTERN = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d+)\s+'
    r'(?P<size>\d+)\s+'
    r'"(?P<referer>[^"]*)"\s+'
    r'"(?P<user_agent>[^"]*)"'
)

NGINX_ERROR_PATTERN = re.compile(
    r'(?P<timestamp>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'\[(?P<level>\w+)\]\s+'
    r'(?P<pid>\d+)#(?P<tid>\d+):\s+'
    r'(?:\*(?P<cid>\d+)\s+)?'
    r'(?P<message>.*?)'
    r'(?:,\s+client:\s+(?P<client_ip>[^,]+))?'
    r'(?:,\s+server:\s+(?P<server>[^,]+))?'
    r'(?:,\s+request:\s+"(?P<request>[^"]+)")?'
    r'(?:,\s+host:\s+"(?P<host>[^"]+)")?'
    r'$'
)

TIMESTAMP_FORMATS = [
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S,%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S,%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
    "%d/%b/%Y:%H:%M:%S %z",
]

ABNORMAL_LEVELS = {"ERROR", "FATAL", "CRITICAL", "WARNING", "WARN"}
NGINX_ERROR_LEVEL_MAP = {
    "alert": "CRITICAL",
    "crit": "CRITICAL",
    "error": "ERROR",
    "warn": "WARNING",
    "notice": "INFO",
    "info": "INFO",
    "debug": "DEBUG",
}

FINGERPRINT_NORMALIZERS = [
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b'), '{IP}'),
    (re.compile(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'), '{UUID}'),
    (re.compile(r'\b\d{13,19}\b'), '{LONG_ID}'),
    (re.compile(r'\b\d{4,}\b'), '{NUMBER}'),
    (re.compile(r'(?<==)\d+'), '{NUMBER}'),
    (re.compile(r'\b(?:order|id|req|request|tx|user)_[a-zA-Z0-9_-]+\b', re.IGNORECASE), '{REF_ID}'),
    (re.compile(r'\b\d+(?:\.\d+)?\s*(?:ms|s|sec|seconds|minutes|hours|days)\b', re.IGNORECASE), '{DURATION}'),
    (re.compile(r'\b\d+(?:\.\d+)?\s*(?:ms|us|ns)\b'), '{DURATION}'),
    (re.compile(r'\bin\s+\d+(?:\.\d+)?\s*(?:ms|s)\b', re.IGNORECASE), 'in {DURATION}'),
    (re.compile(r'time(?:d)?[_\s]?out(?:\s+after)?\s*\d+', re.IGNORECASE), 'timeout after {DURATION}'),
    (re.compile(r'line\s+\d+', re.IGNORECASE), 'line {NUMBER}'),
    (re.compile(r'port\s+\d+', re.IGNORECASE), 'port {NUMBER}'),
    (re.compile(r'code\s+\d+', re.IGNORECASE), 'code {NUMBER}'),
    (re.compile(r'status\s*\d+', re.IGNORECASE), 'status {NUMBER}'),
    (re.compile(r'\b(?:0x)?[0-9a-fA-F]{6,}\b'), '{HEX}'),
    (re.compile(r'at\s+0x[0-9a-fA-F]+\b'), 'at {ADDR}'),
]


def parse_timestamp(ts_str):
    ts_str = ts_str.strip()
    for fmt in TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(ts_str, fmt)
        except ValueError:
            continue
    return None


def load_field_mapping(config_path):
    if not config_path:
        return None
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"字段映射配置文件不存在: {config_path}")
    with open(config_path, "r", encoding="utf-8") as f:
        mapping = json.load(f)
    required = {"timestamp", "level", "message"}
    if not required.issubset(mapping.keys()):
        missing = required - set(mapping.keys())
        raise ValueError(f"字段映射缺少必需字段: {missing}")
    return mapping


def _apply_field_mapping(raw_dict, mapping):
    ts_key = mapping["timestamp"]
    level_key = mapping["level"]
    msg_key = mapping["message"]
    mod_key = mapping.get("module")

    ts_val = str(raw_dict.get(ts_key, "")) if ts_key in raw_dict else ""
    level_val = str(raw_dict.get(level_key, "")).upper() if level_key in raw_dict else ""
    msg_val = str(raw_dict.get(msg_key, "")) if msg_key in raw_dict else ""
    mod_val = str(raw_dict.get(mod_key, "UNKNOWN")) if mod_key and mod_key in raw_dict else "UNKNOWN"

    ts = parse_timestamp(ts_val) if ts_val else None
    return {
        "timestamp": ts,
        "level": level_val or "UNKNOWN",
        "module": mod_val,
        "message": msg_val,
    }


def parse_json_line(line, field_mapping=None):
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(obj, dict):
        return None

    if field_mapping:
        parsed = _apply_field_mapping(obj, field_mapping)
    else:
        ts_val = ""
        for k in ["timestamp", "time", "ts", "@timestamp", "datetime", "date"]:
            if k in obj and obj[k]:
                ts_val = str(obj[k])
                break
        level_val = ""
        for k in ["level", "severity", "log_level", "loglevel"]:
            if k in obj and obj[k]:
                level_val = str(obj[k]).upper()
                break
        msg_val = ""
        for k in ["message", "msg", "content", "log", "text"]:
            if k in obj and obj[k]:
                msg_val = str(obj[k])
                break
        mod_val = "UNKNOWN"
        for k in ["module", "service", "component", "logger", "app"]:
            if k in obj and obj[k]:
                mod_val = str(obj[k])
                break

        ts = parse_timestamp(ts_val) if ts_val else None
        parsed = {
            "timestamp": ts,
            "level": level_val or "UNKNOWN",
            "module": mod_val,
            "message": msg_val,
        }

    parsed["raw"] = line
    return parsed if parsed["message"] else None


def parse_nginx_access_line(line):
    line = line.strip()
    if not line:
        return None
    match = NGINX_ACCESS_PATTERN.match(line)
    if not match:
        return None
    data = match.groupdict()
    ts = parse_timestamp(data.get("timestamp", ""))
    status = int(data.get("status", "0"))
    if status >= 500:
        level = "ERROR"
    elif status >= 400:
        level = "WARNING"
    else:
        level = "INFO"
    method = data.get("method", "")
    path = data.get("path", "")
    message = f'{method} {path} {status} {data.get("size", "")}'
    return {
        "timestamp": ts,
        "level": level,
        "module": "nginx-access",
        "message": message,
        "raw": line,
    }


def parse_nginx_error_line(line):
    line = line.strip()
    if not line:
        return None
    match = NGINX_ERROR_PATTERN.match(line)
    if not match:
        return None
    data = match.groupdict()
    ts = parse_timestamp(data.get("timestamp", ""))
    raw_level = (data.get("level") or "").lower()
    level = NGINX_ERROR_LEVEL_MAP.get(raw_level, "UNKNOWN")
    msg = data.get("message") or ""
    extras = []
    if data.get("client_ip"):
        extras.append(f'client={data["client_ip"]}')
    if data.get("request"):
        extras.append(f'request="{data["request"]}"')
    if data.get("host"):
        extras.append(f'host="{data["host"]}"')
    full_msg = msg
    if extras:
        full_msg = msg + " | " + " ".join(extras)
    return {
        "timestamp": ts,
        "level": level,
        "module": "nginx-error",
        "message": full_msg,
        "raw": line,
    }


def parse_text_line(line):
    line = line.strip()
    if not line:
        return None
    for pattern in TEXT_LOG_PATTERNS:
        match = pattern.match(line)
        if match:
            data = match.groupdict()
            ts = parse_timestamp(data.get("timestamp", ""))
            level = data.get("level", "").upper()
            module = data.get("module") or "UNKNOWN"
            message = data.get("message", "")
            return {
                "timestamp": ts,
                "level": level,
                "module": module,
                "message": message,
                "raw": line,
            }
    return None


def parse_log_line(line, log_format="auto", field_mapping=None):
    if not line or not line.strip():
        return None

    result = None
    stripped = line.strip()

    if log_format == "text":
        result = parse_text_line(stripped)
    elif log_format == "json":
        result = parse_json_line(stripped, field_mapping=field_mapping)
    elif log_format == "nginx-access":
        result = parse_nginx_access_line(stripped)
    elif log_format == "nginx-error":
        result = parse_nginx_error_line(stripped)
    elif log_format == "auto":
        if stripped.startswith("{"):
            result = parse_json_line(stripped, field_mapping=field_mapping)
        if result is None:
            result = parse_nginx_error_line(stripped)
        if result is None:
            result = parse_nginx_access_line(stripped)
        if result is None:
            result = parse_text_line(stripped)

    return result


def normalize_message_for_fingerprint(message):
    if not message:
        return ""
    normalized = message
    for pattern, replacement in FINGERPRINT_NORMALIZERS:
        normalized = pattern.sub(replacement, normalized)
    normalized = re.sub(r'\s+', ' ', normalized).strip()
    return normalized


def compute_fingerprint(level, module, normalized_message):
    raw = f"{level}|{module}|{normalized_message}"
    return hashlib.md5(raw.encode("utf-8")).hexdigest()[:16]


def load_keyword_rules(rules_path):
    if not os.path.exists(rules_path):
        return []
    with open(rules_path, "r", encoding="utf-8") as f:
        rules = json.load(f)
    if not isinstance(rules, list):
        raise ValueError("关键字规则必须是 JSON 数组")
    for rule in rules:
        if "name" not in rule or "pattern" not in rule:
            raise ValueError("每条规则必须包含 'name' 和 'pattern' 字段")
    return rules


def load_alert_rules(rules_path):
    if not rules_path or not os.path.exists(rules_path):
        return None
    with open(rules_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    alerts = data.get("alerts", []) if isinstance(data, dict) else []
    for alert in alerts:
        if "type" not in alert or "threshold" not in alert or "window_minutes" not in alert:
            raise ValueError("每条告警规则必须包含 'type'、'threshold' 和 'window_minutes' 字段")
    return alerts


def match_keywords(message, rules):
    matched = []
    for rule in rules:
        pattern = rule["pattern"]
        flags = 0
        if rule.get("ignore_case", True):
            flags |= re.IGNORECASE
        try:
            if re.search(pattern, message, flags):
                matched.append(rule["name"])
        except re.error:
            continue
    return matched


def assess_risk_level(level, keywords, alert_hits):
    score = 0
    if level in ("FATAL", "CRITICAL"):
        score += 3
    elif level == "ERROR":
        score += 2
    elif level in ("WARNING", "WARN"):
        score += 1
    score += len(keywords) * 2
    score += len(alert_hits) * 3
    if score >= 5:
        return "HIGH"
    elif score >= 3:
        return "MEDIUM"
    elif score >= 1:
        return "LOW"
    return "INFO"


def collect_log_files(path, extensions=None):
    if extensions is None:
        extensions = {".log", ".json", ".jsonl", ".txt"}
    p = Path(path)
    if p.is_file():
        if p.suffix.lower() in extensions:
            return [p]
        return []
    if p.is_dir():
        files = []
        for ext in extensions:
            files.extend(p.rglob(f"*{ext}"))
        return sorted(files)
    return []


def _granularity_keys(ts):
    if not ts:
        return None, None, None
    minute_key = ts.strftime("%Y-%m-%d %H:%M")
    hour_key = ts.strftime("%Y-%m-%d %H:00")
    day_key = ts.strftime("%Y-%m-%d")
    return minute_key, hour_key, day_key


def check_alerts(record, trends, alert_rules):
    hits = []
    ts = record.get("_ts_obj")
    if not alert_rules or not ts:
        return hits
    for rule in alert_rules:
        rtype = rule["type"]
        threshold = rule["threshold"]
        window = int(rule["window_minutes"])
        window_start = ts - timedelta(minutes=window)
        triggered = False
        reason_extra = ""

        if rtype == "keyword":
            target_name = rule.get("keyword")
            if not target_name:
                continue
            if target_name not in record.get("keywords", []):
                continue
            count = 0
            for minute_key, kw_map in trends["_alert_minute_keywords"].items():
                try:
                    bucket_dt = datetime.strptime(minute_key, "%Y-%m-%d %H:%M")
                except ValueError:
                    continue
                if window_start <= bucket_dt <= ts:
                    count += kw_map.get(target_name, 0)
            if count >= threshold:
                triggered = True
                reason_extra = f"关键字[{target_name}]在{window}分钟内出现{count}次"

        elif rtype == "level":
            target_level = rule.get("level", "").upper()
            if not target_level:
                continue
            if record["level"] != target_level:
                continue
            count = 0
            for minute_key, lvl_map in trends["_alert_minute_levels"].items():
                try:
                    bucket_dt = datetime.strptime(minute_key, "%Y-%m-%d %H:%M")
                except ValueError:
                    continue
                if window_start <= bucket_dt <= ts:
                    count += lvl_map.get(target_level, 0)
            if count >= threshold:
                triggered = True
                reason_extra = f"级别[{target_level}]在{window}分钟内出现{count}次"

        if triggered:
            hits.append({
                "rule_type": rtype,
                "threshold": threshold,
                "window_minutes": window,
                "reason": reason_extra,
                "risk": rule.get("risk", "HIGH"),
            })
    return hits


def analyze_logs(
    log_path,
    rules=None,
    alert_rules=None,
    start_time=None,
    end_time=None,
    top_n=10,
    levels=None,
    log_format="auto",
    field_mapping=None,
):
    if rules is None:
        rules = []
    if alert_rules is None:
        alert_rules = []
    if levels is None:
        levels = ABNORMAL_LEVELS

    log_files = collect_log_files(log_path)
    if not log_files:
        return None

    records = []
    level_counter = Counter()
    module_counter = Counter()
    keyword_counter = Counter()
    minute_counter = defaultdict(int)
    hour_counter = defaultdict(int)
    day_counter = defaultdict(int)
    pattern_counter = Counter()
    fingerprint_store = {}
    file_counter = Counter()

    trends_internal = {
        "_alert_minute_keywords": defaultdict(lambda: defaultdict(int)),
        "_alert_minute_levels": defaultdict(lambda: defaultdict(int)),
    }

    for log_file in log_files:
        file_key = str(log_file)
        try:
            with open(log_file, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    parsed = parse_log_line(line, log_format=log_format, field_mapping=field_mapping)
                    if not parsed:
                        continue
                    ts = parsed["timestamp"]
                    if ts and start_time and ts < start_time:
                        continue
                    if ts and end_time and ts > end_time:
                        continue
                    level = parsed["level"]
                    if level not in levels:
                        continue

                    matched_keywords = match_keywords(parsed["message"], rules)

                    min_key, hour_key, day_key = _granularity_keys(ts)
                    if min_key:
                        minute_counter[min_key] += 1
                        for kw in matched_keywords:
                            trends_internal["_alert_minute_keywords"][min_key][kw] += 1
                        trends_internal["_alert_minute_levels"][min_key][level] += 1
                    if hour_key:
                        hour_counter[hour_key] += 1
                    if day_key:
                        day_counter[day_key] += 1

                    normalized = normalize_message_for_fingerprint(parsed["message"])
                    fp = compute_fingerprint(level, parsed["module"], normalized)

                    record = {
                        "file": file_key,
                        "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S") if ts else "",
                        "_ts_obj": ts,
                        "level": level,
                        "module": parsed["module"],
                        "message": parsed["message"],
                        "keywords": matched_keywords,
                        "fingerprint": fp,
                        "normalized_message": normalized,
                        "alert_hits": [],
                        "risk": "INFO",
                    }
                    records.append(record)
                    file_counter[file_key] += 1

                    level_counter[level] += 1
                    module_counter[parsed["module"]] += 1
                    for kw in matched_keywords:
                        keyword_counter[kw] += 1

                    pattern_key = (level, parsed["module"], tuple(matched_keywords))
                    pattern_counter[pattern_key] += 1

                    if fp not in fingerprint_store:
                        fingerprint_store[fp] = {
                            "fingerprint": fp,
                            "level": level,
                            "module": parsed["module"],
                            "normalized_message": normalized,
                            "sample_message": parsed["message"],
                            "first_seen": record["timestamp"],
                            "last_seen": record["timestamp"],
                            "_first_ts": ts,
                            "_last_ts": ts,
                            "count": 0,
                            "modules": set(),
                            "keywords": set(),
                            "source_files": set(),
                        }
                    entry = fingerprint_store[fp]
                    entry["count"] += 1
                    entry["modules"].add(parsed["module"])
                    for kw in matched_keywords:
                        entry["keywords"].add(kw)
                    entry["source_files"].add(file_key)
                    if ts:
                        if entry["_first_ts"] is None or ts < entry["_first_ts"]:
                            entry["_first_ts"] = ts
                            entry["first_seen"] = record["timestamp"]
                        if entry["_last_ts"] is None or ts > entry["_last_ts"]:
                            entry["_last_ts"] = ts
                            entry["last_seen"] = record["timestamp"]
                    if entry["count"] <= 1:
                        entry["sample_message"] = parsed["message"]
        except (OSError, IOError):
            continue

    for rec in records:
        hits = check_alerts(rec, trends_internal, alert_rules)
        rec["alert_hits"] = hits
        rec["risk"] = assess_risk_level(rec["level"], rec["keywords"], hits)
        if rec["risk"] in ("HIGH", "MEDIUM"):
            fp = rec["fingerprint"]
            if fp in fingerprint_store:
                existing = fingerprint_store[fp].get("risk", "INFO")
                order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
                if order.get(rec["risk"], 0) > order.get(existing, 0):
                    fingerprint_store[fp]["risk"] = rec["risk"]

    for fp in fingerprint_store:
        entry = fingerprint_store[fp]
        if "risk" not in entry:
            entry["risk"] = assess_risk_level(entry["level"], list(entry["keywords"]), [])
        entry["modules"] = sorted(entry["modules"])
        entry["keywords"] = sorted(entry["keywords"])
        entry["source_files"] = sorted(entry["source_files"])
        entry.pop("_first_ts", None)
        entry.pop("_last_ts", None)

    top_patterns = []
    for (lvl, mod, kws), count in pattern_counter.most_common(top_n):
        top_patterns.append({
            "count": count,
            "level": lvl,
            "module": mod,
            "keywords": list(kws),
        })

    fp_list = sorted(fingerprint_store.values(), key=lambda x: -x["count"])
    top_fingerprints = fp_list[:top_n]

    high_risk_alerts = []
    seen_combo = set()
    for rec in records:
        if rec["risk"] != "HIGH" or not rec["alert_hits"]:
            continue
        combo_key = (rec["fingerprint"], tuple(a["reason"] for a in rec["alert_hits"]))
        if combo_key in seen_combo:
            continue
        seen_combo.add(combo_key)
        high_risk_alerts.append({
            "timestamp": rec["timestamp"],
            "level": rec["level"],
            "module": rec["module"],
            "message": rec["message"],
            "fingerprint": rec["fingerprint"],
            "file": rec["file"],
            "risk": rec["risk"],
            "alert_hits": rec["alert_hits"],
        })

    trends = {
        "by_minute": dict(sorted(minute_counter.items())),
        "by_hour": dict(sorted(hour_counter.items())),
        "by_day": dict(sorted(day_counter.items())),
    }

    for rec in records:
        rec.pop("_ts_obj", None)

    return {
        "files": [str(f) for f in log_files],
        "file_counts": dict(file_counter),
        "total_records": len(records),
        "records": records,
        "by_level": dict(level_counter),
        "by_module": dict(module_counter),
        "by_keyword": dict(keyword_counter),
        "trends": trends,
        "top_patterns": top_patterns,
        "fingerprints": fp_list,
        "top_fingerprints": top_fingerprints,
        "high_risk_alerts": high_risk_alerts,
    }


def print_report(result, top_n=10):
    print("=" * 70)
    print("日志异常模式分析报告")
    print("=" * 70)

    print(f"\n扫描日志文件数: {len(result['files'])}")
    for f in result["files"]:
        cnt = result["file_counts"].get(f, 0)
        print(f"  - {f}  ({cnt} 条异常)")
    print(f"异常记录总数: {result['total_records']}")

    if result["by_level"]:
        print("\n按日志级别统计:")
        for level, count in sorted(result["by_level"].items(), key=lambda x: -x[1]):
            print(f"  {level:<10} {count}")

    if result["by_module"]:
        limit = min(top_n, len(result["by_module"]))
        print(f"\n按模块统计 (Top {limit}):")
        for module, count in sorted(result["by_module"].items(), key=lambda x: -x[1])[:top_n]:
            print(f"  {module:<30} {count}")

    if result["by_keyword"]:
        limit = min(top_n, len(result["by_keyword"]))
        print(f"\n按关键字规则统计 (Top {limit}):")
        for kw, count in sorted(result["by_keyword"].items(), key=lambda x: -x[1])[:top_n]:
            print(f"  {kw:<30} {count}")

    trends = result["trends"]
    for label, data in [("分钟", trends["by_minute"]), ("小时", trends["by_hour"]), ("天", trends["by_day"])]:
        if data:
            sample_count = min(10, len(data))
            print(f"\n按{label}统计趋势 (显示前{sample_count}条):")
            for i, (bucket, count) in enumerate(data.items()):
                if i >= sample_count:
                    break
                bar = "#" * min(count, 50)
                print(f"  {bucket}  {count:>5}  {bar}")

    if result["top_fingerprints"]:
        print(f"\nTop {top_n} 异常指纹:")
        for i, fp in enumerate(result["top_fingerprints"], 1):
            kws = ", ".join(fp["keywords"]) if fp["keywords"] else "(无匹配)"
            mods = ", ".join(fp["modules"])
            print(f"  #{i:<2} 指纹={fp['fingerprint']} 计数={fp['count']:<5} "
                  f"级别={fp['level']:<8} 风险={fp['risk']:<6}")
            print(f"       首次={fp['first_seen']}  最后={fp['last_seen']}")
            print(f"       模块=[{mods}]  关键字=[{kws}]")
            print(f"       示例: {fp['sample_message'][:100]}")

    if result["high_risk_alerts"]:
        print(f"\n高风险告警列表 ({len(result['high_risk_alerts'])} 条):")
        for i, a in enumerate(result["high_risk_alerts"][:top_n], 1):
            reasons = "; ".join(h["reason"] for h in a["alert_hits"])
            print(f"  #{i:<2} [{a['timestamp']}] {a['level']:<8} {a['module']:<20}")
            print(f"       原因: {reasons}")
            print(f"       消息: {a['message'][:100]}")

    if result["top_patterns"]:
        print(f"\nTop {top_n} 异常模式:")
        for i, p in enumerate(result["top_patterns"], 1):
            kw_str = ", ".join(p["keywords"]) if p["keywords"] else "(无匹配)"
            print(f"  #{i:<2} 计数={p['count']:<5} 级别={p['level']:<8} "
                  f"模块={p['module']:<20} 关键字=[{kw_str}]")

    print("\n" + "=" * 70)


def export_csv(result, output_path):
    records = result["records"]
    if not records:
        return False
    fieldnames = ["file", "timestamp", "level", "module", "fingerprint", "risk", "keywords", "message"]
    with open(output_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in records:
            row = {
                "file": r["file"],
                "timestamp": r["timestamp"],
                "level": r["level"],
                "module": r["module"],
                "fingerprint": r.get("fingerprint", ""),
                "risk": r.get("risk", "INFO"),
                "keywords": ";".join(r["keywords"]),
                "message": r["message"],
            }
            writer.writerow(row)
    return True


def export_markdown(result, output_path, top_n=10):
    lines = []
    lines.append("# 日志异常模式分析报告")
    lines.append("")
    lines.append(f"> 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")

    lines.append("## 总体概览")
    lines.append("")
    lines.append("| 指标 | 数值 |")
    lines.append("| --- | --- |")
    lines.append(f"| 扫描日志文件数 | {len(result['files'])} |")
    lines.append(f"| 异常记录总数 | {result['total_records']} |")
    lines.append(f"| 异常指纹种类数 | {len(result['fingerprints'])} |")
    lines.append(f"| 高风险告警数 | {len(result['high_risk_alerts'])} |")
    lines.append("")

    lines.append("### 扫描文件列表")
    lines.append("")
    lines.append("| 文件 | 异常记录数 |")
    lines.append("| --- | --- |")
    for f in result["files"]:
        lines.append(f"| `{f}` | {result['file_counts'].get(f, 0)} |")
    lines.append("")

    if result["by_level"]:
        lines.append("## 级别统计")
        lines.append("")
        lines.append("| 级别 | 次数 | 占比 |")
        lines.append("| --- | --- | --- |")
        total = sum(result["by_level"].values()) or 1
        for level, count in sorted(result["by_level"].items(), key=lambda x: -x[1]):
            pct = f"{count * 100 / total:.1f}%"
            lines.append(f"| {level} | {count} | {pct} |")
        lines.append("")

    if result["by_module"]:
        lines.append(f"## 模块统计 (Top {min(top_n, len(result['by_module']))})")
        lines.append("")
        lines.append("| 模块 | 次数 |")
        lines.append("| --- | --- |")
        for module, count in sorted(result["by_module"].items(), key=lambda x: -x[1])[:top_n]:
            lines.append(f"| `{module}` | {count} |")
        lines.append("")

    if result["by_keyword"]:
        lines.append(f"## 关键字命中 (Top {min(top_n, len(result['by_keyword']))})")
        lines.append("")
        lines.append("| 关键字 | 命中次数 |")
        lines.append("| --- | --- |")
        for kw, count in sorted(result["by_keyword"].items(), key=lambda x: -x[1])[:top_n]:
            lines.append(f"| {kw} | {count} |")
        lines.append("")

    if result["top_fingerprints"]:
        lines.append(f"## 异常指纹 Top {len(result['top_fingerprints'])}")
        lines.append("")
        lines.append("| # | 指纹 | 次数 | 级别 | 风险 | 首次出现 | 最后出现 | 模块 | 示例消息 |")
        lines.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
        for i, fp in enumerate(result["top_fingerprints"], 1):
            mods = ", ".join(fp["modules"])
            sample = (fp["sample_message"] or "")[:80].replace("|", "\\|")
            lines.append(
                f"| {i} | `{fp['fingerprint']}` | {fp['count']} | {fp['level']} | {fp['risk']} "
                f"| {fp['first_seen']} | {fp['last_seen']} | {mods} | {sample} |"
            )
        lines.append("")

    lines.append("## 时间趋势")
    lines.append("")
    for label, data in [
        ("按天统计", result["trends"]["by_day"]),
        ("按小时统计", result["trends"]["by_hour"]),
        ("按分钟统计", result["trends"]["by_minute"]),
    ]:
        if data:
            lines.append(f"### {label}")
            lines.append("")
            lines.append("| 时间 | 异常次数 |")
            lines.append("| --- | --- |")
            for bucket, count in data.items():
                lines.append(f"| {bucket} | {count} |")
            lines.append("")

    if result["high_risk_alerts"]:
        lines.append(f"## 高风险告警列表 ({len(result['high_risk_alerts'])})")
        lines.append("")
        lines.append("| # | 时间 | 级别 | 模块 | 风险 | 告警原因 | 消息摘要 | 来源文件 |")
        lines.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
        for i, a in enumerate(result["high_risk_alerts"], 1):
            reasons = "; ".join(h["reason"] for h in a["alert_hits"]).replace("|", "\\|")
            msg = (a["message"] or "")[:80].replace("|", "\\|")
            src = a["file"]
            lines.append(
                f"| {i} | {a['timestamp']} | {a['level']} | {a['module']} | {a['risk']} "
                f"| {reasons} | {msg} | `{src}` |"
            )
        lines.append("")

    lines.append("---")
    lines.append("*报告由日志异常模式分析器自动生成*")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return True


def serialize_for_json(result):
    return {
        "files": result["files"],
        "file_counts": result["file_counts"],
        "total_records": result["total_records"],
        "by_level": result["by_level"],
        "by_module": result["by_module"],
        "by_keyword": result["by_keyword"],
        "trends": result["trends"],
        "top_patterns": result["top_patterns"],
        "top_fingerprints": result["top_fingerprints"],
        "high_risk_alerts": result["high_risk_alerts"],
    }


def parse_time_arg(s):
    if not s:
        return None
    for fmt in TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    try:
        return datetime.strptime(s, "%Y-%m-%d")
    except ValueError:
        pass
    raise argparse.ArgumentTypeError(f"无法解析时间: {s}")


def build_arg_parser():
    parser = argparse.ArgumentParser(
        description="本地日志文件异常模式分析器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python log_analyzer.py ./logs
  python log_analyzer.py ./logs -r rules.json --top 20
  python log_analyzer.py app.log --start "2024-01-01 00:00:00" --end "2024-01-02 00:00:00"
  python log_analyzer.py ./logs -o report.csv --markdown report.md
  python log_analyzer.py app.jsonl --format json
  python log_analyzer.py access.log --format nginx-access
  python log_analyzer.py custom.log --mapping field_map.json
  python log_analyzer.py ./logs -r rules.json --alert-rules alerts.json
        """,
    )
    parser.add_argument("path", help="日志文件或目录路径")
    parser.add_argument("-r", "--rules", help="自定义关键字规则 JSON 文件路径")
    parser.add_argument("--alert-rules", dest="alert_rules", help="告警规则 JSON 文件路径")
    parser.add_argument("--start", type=parse_time_arg, help="起始时间 (格式: YYYY-MM-DD HH:MM:SS)")
    parser.add_argument("--end", type=parse_time_arg, help="结束时间 (格式: YYYY-MM-DD HH:MM:SS)")
    parser.add_argument("--top", type=int, default=10, help="Top N 异常模式数量 (默认: 10)")
    parser.add_argument("-o", "--output", help="导出 CSV 报告的输出路径")
    parser.add_argument("--markdown", help="导出 Markdown 报告的输出路径")
    parser.add_argument(
        "--levels",
        default="ERROR,FATAL,CRITICAL,WARNING,WARN",
        help="要分析的日志级别，逗号分隔 (默认: ERROR,FATAL,CRITICAL,WARNING,WARN)",
    )
    parser.add_argument("--json", action="store_true", help="以 JSON 格式输出分析结果")
    parser.add_argument(
        "--format",
        dest="log_format",
        default="auto",
        choices=["auto", "text", "json", "nginx-access", "nginx-error"],
        help="日志格式 (默认: auto)",
    )
    parser.add_argument(
        "--mapping",
        dest="field_mapping",
        help="字段映射配置 JSON 文件路径 (用于自定义 JSON 日志的字段名)",
    )
    return parser


def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    if not os.path.exists(args.path):
        print(f"错误: 路径不存在: {args.path}", file=sys.stderr)
        return 1

    rules = []
    if args.rules:
        if not os.path.exists(args.rules):
            print(f"错误: 规则文件不存在: {args.rules}", file=sys.stderr)
            return 1
        try:
            rules = load_keyword_rules(args.rules)
        except (json.JSONDecodeError, ValueError) as e:
            print(f"错误: 加载规则文件失败: {e}", file=sys.stderr)
            return 1

    alert_rules = []
    if args.alert_rules:
        if not os.path.exists(args.alert_rules):
            print(f"错误: 告警规则文件不存在: {args.alert_rules}", file=sys.stderr)
            return 1
        try:
            loaded = load_alert_rules(args.alert_rules)
            if loaded is not None:
                alert_rules = loaded
        except (json.JSONDecodeError, ValueError) as e:
            print(f"错误: 加载告警规则失败: {e}", file=sys.stderr)
            return 1

    field_mapping = None
    if args.field_mapping:
        try:
            field_mapping = load_field_mapping(args.field_mapping)
        except (FileNotFoundError, ValueError, json.JSONDecodeError) as e:
            print(f"错误: 加载字段映射配置失败: {e}", file=sys.stderr)
            return 1

    levels = {lvl.strip().upper() for lvl in args.levels.split(",") if lvl.strip()}

    result = analyze_logs(
        args.path,
        rules=rules,
        alert_rules=alert_rules,
        start_time=args.start,
        end_time=args.end,
        top_n=args.top,
        levels=levels,
        log_format=args.log_format,
        field_mapping=field_mapping,
    )

    if result is None:
        print(f"警告: 未找到日志文件: {args.path}", file=sys.stderr)
        return 1

    if args.json:
        output = serialize_for_json(result)
        print(json.dumps(output, ensure_ascii=False, indent=2))
    else:
        print_report(result, top_n=args.top)

    if args.output:
        if export_csv(result, args.output):
            print(f"CSV 报告已导出: {args.output}")
        else:
            print("警告: 没有可导出的记录", file=sys.stderr)

    if args.markdown:
        if export_markdown(result, args.markdown, top_n=args.top):
            print(f"Markdown 报告已导出: {args.markdown}")
        else:
            print("警告: Markdown 导出失败", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
