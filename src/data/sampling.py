import numpy as np
import pandas as pd


ATTACK_TYPES = [
    "DDoS-HTTP Flood",
    "DoS-HTTP Flood",
    "DNS Spoofing",
    "Brute Force",
    "XSS",
]

EXPECTED_PACKET_TYPES = ["Benign"] + ATTACK_TYPES

@dataclass
class SamplingConfig:
    benign_rows: int = 200_000
    attack_min_rows: int = 4_000
    attack_max_rows: int = 6_200
    min_rows_per_attack: int = 200
    seed: int | None = None
    chunksize: int = 50_000

def normalize_file_name(path: Path) -> str:
    name = path.name.lower()
    name = name.replace(".pcap_flow.csv", "")
    name = name.replace(".csv", "")
    name = name.replace("-", "_")
    name = name.replace(" ", "_")

    while "__" in name:
        name = name.replace("__", "_")

    return name.strip("_")

def infer_traffic_level(path: Path) -> str:
    if path.name.lower().endswith(".pcap_flow.csv"):
        return "flow-level"
    return "packet-level"


def infer_attack_type(path: Path) -> str:
    name = normalize_file_name(path)

    if "benign" in name:
        return "Benign"

    if "ddos" in name and "http" in name and "flood" in name:
        return "DDoS-HTTP Flood"

    if name.startswith("dos") and "http" in name and "flood" in name:
        return "DoS-HTTP Flood"

    if "dns" in name and "spoofing" in name:
        return "DNS Spoofing"

    if "dictionarybruteforce" in name or "bruteforce" in name or "brute_force" in name:
        return "Brute Force"

    if "xss" in name:
        return "XSS"

    return "Unknown"
