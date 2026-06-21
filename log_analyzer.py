#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import csv
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path


LOG_PATTERNS = [
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

TIMESTAMP_FORMATS = [
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S,%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S,%f",
    "%Y-%m-%d %H:%M:%S",
]

ABNORMAL_LEVELS = {"ERROR", "FATAL", "CRITICAL", "WARNING", "WARN"}


def parse_timestamp(ts_str):
    ts_str = ts_str.strip()
    for fmt in TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(ts_str, fmt)
        except ValueError:
            continue
    return None


def parse_log_line(line):
    line = line.strip()
    if not line:
        return None
    for pattern in LOG_PATTERNS:
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


def collect_log_files(path):
    p = Path(path)
    if p.is_file():
        if p.suffix.lower() == ".log":
            return [p]
        return []
    if p.is_dir():
        return sorted(p.rglob("*.log"))
    return []


def analyze_logs(
    log_path,
    rules=None,
    start_time=None,
    end_time=None,
    top_n=10,
    levels=None,
):
    if rules is None:
        rules = []
    if levels is None:
        levels = ABNORMAL_LEVELS

    log_files = collect_log_files(log_path)
    if not log_files:
        return None

    records = []
    level_counter = Counter()
    module_counter = Counter()
    keyword_counter = Counter()
    hourly_counter = defaultdict(int)
    pattern_counter = Counter()

    for log_file in log_files:
        try:
            with open(log_file, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    parsed = parse_log_line(line)
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

                    record = {
                        "file": str(log_file),
                        "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S") if ts else "",
                        "level": level,
                        "module": parsed["module"],
                        "message": parsed["message"],
                        "keywords": matched_keywords,
                    }
                    records.append(record)

                    level_counter[level] += 1
                    module_counter[parsed["module"]] += 1
                    for kw in matched_keywords:
                        keyword_counter[kw] += 1
                    if ts:
                        hour_key = ts.strftime("%Y-%m-%d %H:00")
                        hourly_counter[hour_key] += 1

                    pattern_key = (level, parsed["module"], tuple(matched_keywords))
                    pattern_counter[pattern_key] += 1
        except (OSError, IOError):
            continue

    top_patterns = []
    for (level, module, keywords), count in pattern_counter.most_common(top_n):
        top_patterns.append({
            "count": count,
            "level": level,
            "module": module,
            "keywords": list(keywords),
        })

    return {
        "files": [str(f) for f in log_files],
        "total_records": len(records),
        "records": records,
        "by_level": dict(level_counter),
        "by_module": dict(module_counter),
        "by_keyword": dict(keyword_counter),
        "by_hour": dict(sorted(hourly_counter.items())),
        "top_patterns": top_patterns,
    }


def print_report(result, top_n=10):
    print("=" * 70)
    print("日志异常模式分析报告")
    print("=" * 70)

    print(f"\n扫描日志文件数: {len(result['files'])}")
    for f in result["files"]:
        print(f"  - {f}")
    print(f"异常记录总数: {result['total_records']}")

    if result["by_level"]:
        print("\n按日志级别统计:")
        for level, count in sorted(result["by_level"].items(), key=lambda x: -x[1]):
            print(f"  {level:<10} {count}")

    if result["by_module"]:
        print(f"\n按模块统计 (Top {min(top_n, len(result['by_module']))}):")
        for module, count in sorted(result["by_module"].items(), key=lambda x: -x[1])[:top_n]:
            print(f"  {module:<30} {count}")

    if result["by_keyword"]:
        print(f"\n按关键字规则统计 (Top {min(top_n, len(result['by_keyword']))}):")
        for kw, count in sorted(result["by_keyword"].items(), key=lambda x: -x[1])[:top_n]:
            print(f"  {kw:<30} {count}")

    if result["by_hour"]:
        print("\n按小时统计趋势:")
        for hour, count in result["by_hour"].items():
            bar = "#" * min(count, 50)
            print(f"  {hour}  {count:>5}  {bar}")

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
    fieldnames = ["file", "timestamp", "level", "module", "keywords", "message"]
    with open(output_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in records:
            row = {
                "file": r["file"],
                "timestamp": r["timestamp"],
                "level": r["level"],
                "module": r["module"],
                "keywords": ";".join(r["keywords"]),
                "message": r["message"],
            }
            writer.writerow(row)
    return True


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
  python log_analyzer.py ./logs -o report.csv
        """,
    )
    parser.add_argument("path", help="日志文件或目录路径")
    parser.add_argument("-r", "--rules", help="自定义关键字规则 JSON 文件路径")
    parser.add_argument("--start", type=parse_time_arg, help="起始时间 (格式: YYYY-MM-DD HH:MM:SS)")
    parser.add_argument("--end", type=parse_time_arg, help="结束时间 (格式: YYYY-MM-DD HH:MM:SS)")
    parser.add_argument("--top", type=int, default=10, help="Top N 异常模式数量 (默认: 10)")
    parser.add_argument("-o", "--output", help="导出 CSV 报告的输出路径")
    parser.add_argument(
        "--levels",
        default="ERROR,FATAL,CRITICAL,WARNING,WARN",
        help="要分析的日志级别，逗号分隔 (默认: ERROR,FATAL,CRITICAL,WARNING,WARN)",
    )
    parser.add_argument("--json", action="store_true", help="以 JSON 格式输出分析结果")
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

    levels = {lvl.strip().upper() for lvl in args.levels.split(",") if lvl.strip()}

    result = analyze_logs(
        args.path,
        rules=rules,
        start_time=args.start,
        end_time=args.end,
        top_n=args.top,
        levels=levels,
    )

    if result is None:
        print(f"警告: 未找到 .log 文件: {args.path}", file=sys.stderr)
        return 1

    if args.json:
        output = {
            "files": result["files"],
            "total_records": result["total_records"],
            "by_level": result["by_level"],
            "by_module": result["by_module"],
            "by_keyword": result["by_keyword"],
            "by_hour": result["by_hour"],
            "top_patterns": result["top_patterns"],
        }
        print(json.dumps(output, ensure_ascii=False, indent=2))
    else:
        print_report(result, top_n=args.top)

    if args.output:
        if export_csv(result, args.output):
            print(f"CSV 报告已导出: {args.output}")
        else:
            print("警告: 没有可导出的记录", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
