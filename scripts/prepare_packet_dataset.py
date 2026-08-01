import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit, train_test_split


BINARY_COL = "binary_label"
ATTACK_COL = "attack_type"
PACKET_ID_COL = "packet_id"
PACKET_FLOW_KEY_COL = "packet_flow_key"


def load_packet_dataset(path):
    df = pd.read_csv(path, low_memory=False)
    df.columns = [str(col).strip() for col in df.columns]
    return df


# def validate_packet_dataset(df):
#     required = [BINARY_COL, ATTACK_COL]
#     missing = [col for col in required if col not in df.columns]

#     if missing:
#         raise ValueError(f"Missing required columns: {missing}")
#     if df[required].isna().any().any():
#         raise ValueError("The label columns contain missing values")

#     invalid_labels = sorted(set(df[BINARY_COL].astype(str)) - {"benign", "attack"})
#     if invalid_labels:
#         raise ValueError(f"Unexpected binary labels: {invalid_labels}")


def add_split_keys(df):
    df = df.copy()
    source_file = df.get("source_file", pd.Series("unknown", index=df.index)).fillna("unknown").astype(str)
    stream = pd.to_numeric(df.get("stream", -1), errors="coerce").fillna(-1).astype("int64")

    src_ip = df.get("src_ip", pd.Series("missing", index=df.index)).fillna("missing").astype(str)
    dst_ip = df.get("dst_ip", pd.Series("missing", index=df.index)).fillna("missing").astype(str)
    src_port = pd.to_numeric(df.get("src_port", 0), errors="coerce").fillna(0).astype("int64").astype(str)
    dst_port = pd.to_numeric(df.get("dst_port", 0), errors="coerce").fillna(0).astype("int64").astype(str)
    src_mac = df.get("src_mac", pd.Series("missing", index=df.index)).fillna("missing").astype(str)
    dst_mac = df.get("dst_mac", pd.Series("missing", index=df.index)).fillna("missing").astype(str)

    tcp = pd.to_numeric(df.get("l4_tcp", 0), errors="coerce").fillna(0).eq(1)
    udp = pd.to_numeric(df.get("l4_udp", 0), errors="coerce").fillna(0).eq(1)
    protocol = np.select([tcp, udp], ["TCP", "UDP"], default="OTHER")

    stream_key = source_file + "::stream-" + stream.astype(str)
    fallback_key = source_file + "::" + src_ip + "-" + dst_ip + "-" + src_port + "-" + dst_port + "-" + protocol + "-" + src_mac + "-" + dst_mac
    df[PACKET_FLOW_KEY_COL] = np.where(stream.ge(0), stream_key, fallback_key)
    df[PACKET_ID_COL] = source_file + "::packet-" + pd.Series(np.arange(len(df)), index=df.index).astype(str)
    return df


def distribution_distance(reference, candidate):
    reference_rate = reference.value_counts(normalize=True)
    candidate_rate = candidate.value_counts(normalize=True)
    labels = reference_rate.index.union(candidate_rate.index)
    difference = reference_rate.reindex(labels, fill_value=0) - candidate_rate.reindex(labels, fill_value=0)
    return float(difference.abs().sum())


def best_group_split(df, test_size, seed, attempts=80):
    best = None
    groups = df[PACKET_FLOW_KEY_COL]
    required_types = set(df[ATTACK_COL].unique())

    for offset in range(attempts):
        splitter = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=seed + offset)
        left_idx, right_idx = next(splitter.split(df, groups=groups))
        left = df.iloc[left_idx]
        right = df.iloc[right_idx]

        if required_types - set(left[ATTACK_COL].unique()) or required_types - set(right[ATTACK_COL].unique()):
            continue

        size_error = abs(len(right) / len(df) - test_size)
        class_error = distribution_distance(df[ATTACK_COL], right[ATTACK_COL])
        score = size_error + class_error

        if best is None or score < best[0]:
            best = score, left_idx, right_idx

    return best[1], best[2]


def split_packet_dataset(df, validation_size=0.15, test_size=0.15, seed=1, group_by_flow=True):
    if group_by_flow:
        train_val_idx, test_idx = best_group_split(df, test_size, seed)
        train_val = df.iloc[train_val_idx].reset_index(drop=True)
        test = df.iloc[test_idx].reset_index(drop=True)
        validation_share = validation_size / (1 - test_size)
        train_idx, validation_idx = best_group_split(train_val, validation_share, seed + 1000)
        train = train_val.iloc[train_idx].reset_index(drop=True)
        validation = train_val.iloc[validation_idx].reset_index(drop=True)
    else:
        train_val, test = train_test_split(df, test_size=test_size, stratify=df[ATTACK_COL], random_state=seed)
        validation_share = validation_size / (1 - test_size)
        train, validation = train_test_split(train_val, test_size=validation_share, stratify=train_val[ATTACK_COL], random_state=seed)
        train = train.reset_index(drop=True)
        validation = validation.reset_index(drop=True)
        test = test.reset_index(drop=True)

    return train, validation, test


def class_counts(df, column):
    return {str(name): int(count) for name, count in df[column].value_counts().items()}


def split_overlap(train, validation, test):
    train_keys = set(train[PACKET_FLOW_KEY_COL])
    validation_keys = set(validation[PACKET_FLOW_KEY_COL])
    test_keys = set(test[PACKET_FLOW_KEY_COL])
    return {
        "train_validation": len(train_keys & validation_keys),
        "train_test": len(train_keys & test_keys),
        "validation_test": len(validation_keys & test_keys),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-path", default="data/samples/packet_sample_seed1.csv")
    parser.add_argument("--output-dir", default="data/processed/phase3_packet")
    parser.add_argument("--validation-size", type=float, default=0.15)
    parser.add_argument("--test-size", type=float, default=0.15)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--row-level-split", action="store_true")
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parents[1]
    input_path = project_root / args.input_path
    output_dir = project_root / args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    df = load_packet_dataset(input_path)
    # validate_packet_dataset(df)
    df = add_split_keys(df)

    train, validation, test = split_packet_dataset(
        df,
        validation_size=args.validation_size,
        test_size=args.test_size,
        seed=args.seed,
        group_by_flow=not args.row_level_split,
    )

    train.to_csv(output_dir / "packet_train.csv", index=False)
    validation.to_csv(output_dir / "packet_validation.csv", index=False)
    test.to_csv(output_dir / "packet_test.csv", index=False)

    metadata = {
        "input_path": args.input_path,
        "output_dir": args.output_dir,
        "seed": args.seed,
        "validation_size": args.validation_size,
        "test_size": args.test_size,
        "group_by_flow": not args.row_level_split,
        "group_column": PACKET_FLOW_KEY_COL,
        "packet_id_column": PACKET_ID_COL,
        "split_rows": {"train": len(train), "validation": len(validation), "test": len(test)},
        "binary_counts": {
            "train": class_counts(train, BINARY_COL),
            "validation": class_counts(validation, BINARY_COL),
            "test": class_counts(test, BINARY_COL),
        },
        "attack_type_counts": {
            "train": class_counts(train, ATTACK_COL),
            "validation": class_counts(validation, ATTACK_COL),
            "test": class_counts(test, ATTACK_COL),
        },
        "flow_key_overlap": split_overlap(train, validation, test),
        "feature_preprocessing": "None. Model-specific preprocessing is performed inside each notebook.",
    }

    metadata_path = output_dir / "packet_split_metadata.json"
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    print("Saved raw packet splits to:", output_dir)
    print("Rows:", metadata["split_rows"])
    print("Flow-key overlap:", metadata["flow_key_overlap"])


if __name__ == "__main__":
    main()
