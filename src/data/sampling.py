import numpy as np
import pandas as pd
from pathlib import Path
import json


ATTACK_FILES = {
    "DDoS-HTTP Flood": "DDoS-HTTP_Flood-.csv",
    "DoS-HTTP Flood": "DoS-HTTP_Flood.csv",
    "DNS Spoofing": "DNS_Spoofing.csv",
    "Brute Force": "DictionaryBruteForce.csv",
    "XSS": "XSS.csv",
}

BENIGN_FILE = "BenignTraffic.csv"


def sample_one_file(file_path, n_rows, attack_type, seed=None):
    """
    Read one CSV file and randomly sample n_rows from it.
    """
    df = pd.read_csv(file_path, low_memory=False)

    sample_df = df.sample(n=n_rows, random_state=seed).copy()

    sample_df["attack_type"] = attack_type
    sample_df["binary_label"] = "benign" if attack_type == "Benign" else "attack"
    sample_df["source_file"] = file_path.name

    return sample_df


def generate_random_packet_dataset(
    data_dir="data",
    output_path="data/samples/packet_sample.csv",
    benign_rows=200,
    attack_min_rows=4000,
    attack_max_rows=6200,
    seed=None,
):
    data_dir = Path(data_dir)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    rng = np.random.default_rng(seed)

    all_samples = []

    benign_path = data_dir / BENIGN_FILE
    print(f"Sampling {benign_rows} rows from {BENIGN_FILE}")

    benign_sample = sample_one_file(
        file_path=benign_path,
        n_rows=benign_rows,
        attack_type="Benign",
        seed=seed,
    )

    all_samples.append(benign_sample)

    final_df = pd.concat(all_samples, ignore_index=True)
    final_df.to_csv(output_path, index=False)



if __name__ == "__main__":
    generate_random_packet_dataset(seed=1)