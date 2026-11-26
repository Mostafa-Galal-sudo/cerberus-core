import math
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime
from statistics import mean, pstdev

FEATURE_NAMES = (
    "event_count",
    "rate_per_sec",
    "payload_mean",
    "payload_std",
    "payload_max",
    "payload_min",
    "gap_mean",
    "gap_std",
    "gap_cv",
    "topic_count",
    "topic_entropy",
    "qos_mean",
    "publish_share",
    "size_diversity",
)


def _intervals(times):
    return [b - a for a, b in zip(times, times[1:])]


def _entropy(labels):
    n = len(labels)
    if n <= 1:
        return 0.0
    counts = Counter(labels)
    if len(counts) <= 1:
        return 0.0
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def feature_row(device_id, window_start, window, window_sec):
    times = [t for t, _ in window]
    items = [i for _, i in window]
    gaps = _intervals(times)
    sizes = [i["payload_size"] for i in items]
    topic_list = [i["topic"] for i in items]
    topics = set(topic_list)
    qos = [i["qos"] for i in items]
    published = sum(1 for i in items if i["direction"] == "publish")

    gap_mean = mean(gaps) if gaps else 0.0
    gap_std = pstdev(gaps) if len(gaps) > 1 else 0.0

    return {
        "device_id": device_id,
        "window_start": window_start,
        "event_count": len(items),
        "rate_per_sec": len(items) / window_sec,
        "payload_mean": mean(sizes),
        "payload_std": pstdev(sizes) if len(sizes) > 1 else 0.0,
        "payload_max": max(sizes),
        "payload_min": min(sizes),
        "gap_mean": gap_mean,
        "gap_std": gap_std,
        "gap_cv": (gap_std / gap_mean) if gap_mean else 0.0,
        "topic_count": len(topics),
        "topic_entropy": _entropy(topic_list),
        "qos_mean": mean(qos),
        "publish_share": published / len(items),
        "size_diversity": len(set(sizes)) / len(items),
    }


def device_windows(conn, window_sec=60, step_sec=30, min_events=2):
    rows = conn.execute(
        "SELECT ts_utc, device_id, topic, qos, payload_size, direction "
        "FROM mqtt_events ORDER BY device_id, ts_utc"
    ).fetchall()

    by_device = defaultdict(list)
    for r in rows:
        by_device[r["device_id"]].append(r)

    result = []
    for device_id, items in by_device.items():
        times = [datetime.fromisoformat(i["ts_utc"]).timestamp() for i in items]
        start = times[0]
        end = times[-1]
        while start + window_sec <= end + 1e-9:
            window = [(t, i) for t, i in zip(times, items) if start <= t < start + window_sec]
            if len(window) >= min_events:
                result.append(feature_row(device_id, start, window, window_sec))
            start += step_sec
        if start < end:
            tail = [(t, i) for t, i in zip(times, items) if t >= start]
            if len(tail) >= min_events:
                tail_sec = max(end - start, 1e-6)
                result.append(feature_row(device_id, start, tail, tail_sec))
    return result


def to_matrix(rows):
    import numpy as np

    x = np.array([[r[name] for name in FEATURE_NAMES] for r in rows], dtype=float)
    meta = [{"device_id": r["device_id"], "window_start": r["window_start"]} for r in rows]
    return x, meta
