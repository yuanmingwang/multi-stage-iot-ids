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


def split_attack_rows(total_attack_rows, min_each=200, seed=None):
    """
    Randomly split attack rows across five attack types.
    """
    rng = np.random.default_rng(seed)
    attack_names = list(ATTACK_FILES.keys())

    remaining = total_attack_rows - min_each * len(attack_names)

    weights = rng.dirichlet(np.ones(len(attack_names)))
    extra_rows = rng.multinomial(remaining, weights)

    attack_counts = {}

    for attack_name, extra in zip(attack_names, extra_rows):
        attack_counts[attack_name] = int(min_each + extra)

    return attack_counts


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
    data_dir="data/raw",
    output_path="data/samples/packet_sample.csv",
    benign_rows=200000,
    attack_min_rows=4000,
    attack_max_rows=6200,
    min_attack_each=200,
    seed=1,
):
    """
    Generate the Task 1.1 random packet-level dataset.

    Default output:
    - 200,000 benign rows
    - 4,000 to 6,200 attack rows
    - attack rows randomly split across five attack types
    """
    data_dir = Path(data_dir)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    rng = np.random.default_rng(seed)

    total_attack_rows = rng.integers(attack_min_rows, attack_max_rows + 1)
    attack_counts = split_attack_rows(
        total_attack_rows,
        min_each=min_attack_each,
        seed=seed,
    )

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

    for attack_type, file_name in ATTACK_FILES.items():
        file_path = data_dir / file_name
        n_rows = attack_counts[attack_type]

        print(f"Sampling {n_rows} rows from {file_name}")

        attack_sample = sample_one_file(
            file_path=file_path,
            n_rows=n_rows,
            attack_type=attack_type,
            seed=seed,
        )

        all_samples.append(attack_sample)

    final_df = pd.concat(all_samples, ignore_index=True)

    # Shuffle after combining benign and attack rows
    final_df = final_df.sample(frac=1, random_state=seed).reset_index(drop=True)

    final_df.to_csv(output_path, index=False)

    metadata = {
        "output_path": str(output_path),
        "seed": seed,
        "benign_rows": int(benign_rows),
        "total_attack_rows": int(total_attack_rows),
        "attack_counts": {k: int(v) for k, v in attack_counts.items()},
        "total_rows": int(len(final_df)),
        "binary_counts": {
            k: int(v)
            for k, v in final_df["binary_label"].value_counts().to_dict().items()
        },
        "attack_type_counts": {
            k: int(v)
            for k, v in final_df["attack_type"].value_counts().to_dict().items()
        },
    }

    metadata_path = output_path.with_suffix(".metadata.json")

    with open(metadata_path, "w") as f:
        json.dump(metadata, f, indent=2)

    print("\nSampling finished.")
    print(f"Saved dataset to: {output_path}")
    print(f"Saved metadata to: {metadata_path}")
    print("\nClass counts:")
    print(final_df["attack_type"].value_counts())

    return final_df


if __name__ == "__main__":
    generate_random_packet_dataset(seed=1)