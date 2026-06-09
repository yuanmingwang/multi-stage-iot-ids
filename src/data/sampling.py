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
    seed: int | None = 1 # default seed = 1
    benign_rows: int = 200000
    attack_min_rows: int = 4000
    attack_max_rows: int = 6200
    min_rows_per_attack: int = 200
    chunksize: int = 50000

