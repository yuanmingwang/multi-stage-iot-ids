# Code Walkthrough — Multi-Stage IoT IDS

This document explains what each major module and script does, why it exists, and how data moves through the system. Use it to understand the pipeline end-to-end before a demo or report write-up.

---

## 1. Big picture

```
data/raw/*.csv
      │
      ├─► Phase 1: sample packets  ──► data/samples/packet_sample_*.csv
      │                                      │
      │                                      ▼
      │                               Phase 2: Isolation Forest
      │                               (unsupervised packet alerts)
      │                                      │
      ├─► Phase 1: sample flows   ──► data/samples/flow_sample_*.csv
      │                                      │
      │                                      ▼
      │                               prepare splits ──► data/processed/phase3/
      │                                      │
      │                                      ▼
      │                               Phase 3: XGBoost / RF / SVM
      │                               (supervised flow classifier)
      │                                      │
      └─► (on Phase-2 alerts only)           │
             packet → Flow ID link ──────────┘
                           │
                           ▼
                    Two-stage cascade
              (alert only if Phase 2 AND Phase 3 agree)
```

**Design idea:** Phase 2 casts a wide net on packets (catches floods well, but raises false positives). Phase 3 looks at the corresponding *flow* statistics and filters out alerts that look benign at the flow level.

---

## 2. Phase 1 — packet sampling

### File: `src/data/sampling.py`

| Function | What it does | Why |
|---|---|---|
| `split_attack_rows(total, min_each, seed)` | Splits a random attack budget across the five attack types. Each type gets at least `min_each` rows; the rest is drawn with a Dirichlet → multinomial so every run can look different. | Assignment asks for ~4k–6.2k attacks randomly distributed across five classes. |
| `sample_one_file(path, n_rows, attack_type, seed)` | Reads one CSV, samples `n_rows`, and attaches `attack_type`, `binary_label`, `source_file`. | Keeps sampling logic per-file so benign and each attack file are handled the same way. |
| `generate_random_packet_dataset(...)` | Orchestrates full Task 1.1 sample: 200k benign + random attack count, shuffle, write CSV + `.metadata.json`. | Produces the imbalanced packet dataset Phase 2 trains on. |

**Labels added (not original CIC columns):**
- `attack_type` — Benign / DDoS-HTTP Flood / …
- `binary_label` — `benign` or `attack`
- `source_file` — which raw file the row came from (must **not** be used as a model feature; it leaks the label)

### Script: `scripts/generate_random_packet_sample.py`

Thin CLI wrapper. Parses `--data-dir`, `--output-path`, `--seed`, etc., and calls `generate_random_packet_dataset`.

**Example:**
```bash
python scripts/generate_random_packet_sample.py \
  --data-dir data/raw \
  --output-path data/samples/packet_sample_seed1.csv \
  --seed 1
```

---

## 3. Phase 1 — flow sampling and segment aggregation

### File: `src/data/flow_sampling.py`

CICFlowMeter splits long flows into ~2-minute segments that share the same `Flow ID`. This module samples unique flows, then collapses segments into one row per flow.

| Function / piece | What it does | Why |
|---|---|---|
| `ATTACK_FILE_NAMES` / `BENIGN_FILE_NAME` | Maps attack names → `*.pcap_Flow.csv` filenames. | Flow files use different names than packet files. |
| `SUM_COLUMNS`, `MAX_COLUMNS`, `MIN_COLUMNS`, `MEAN_COLUMNS`, … | Declare how each feature should be aggregated when merging segments. | Counts/durations should be summed; maxima stay max; rates are recomputed after merge. |
| `_read_csv` | Reads CSV; falls back to `latin1` if UTF-8 fails. | Some CIC exports have encoding quirks. |
| `_available_flow_ids(path, chunksize)` | Scans a large flow file in chunks and collects unique `Flow ID`s. | Files are huge; we cannot load everything into memory just to list IDs. |
| `_allocate_attack_counts(...)` | Like packet attack split, but respects how many unique flows each class actually has. | Brute Force / XSS have far fewer unique flows than floods. |
| `_prepare_segments(df)` | Cleans types, parses timestamps, replaces ±inf with NaN, builds helper count columns for mean/std recombination. | Prepares segments so aggregation is statistically valid. |
| `_combine_mean_std(...)` | Correctly merges per-segment mean/std into one mean/std using counts (not a naive average of means). | Averaging means without weights is wrong when segments have different sizes. |
| `aggregate_flow_segments(df)` | Groups by `Flow ID`, applies sum/max/min/mean/first rules, recomputes rates like `Flow Bytes/s`. | One unified flow record for supervised learning. |
| `generate_random_flow_dataset(...)` | Full Task 3.2-style flow sample: scan IDs → sample → load segments → aggregate → shuffle → save + metadata. | Training set for Phase 3. Note: only ~123k unique benign flows exist, so we use all of them if 200k are requested. |

### Script: `scripts/generate_random_flow_sample.py`

CLI around `generate_random_flow_dataset`.

---

## 4. Phase 3 data prep (flow splits)

### File: `src/data/flow_preprocessing.py`

| Function | What it does | Why |
|---|---|---|
| `load_flow_dataset(path)` | Reads CSV; strips column-name whitespace. | Defensive cleaning. |
| `clean_flow_dataset(df)` | Keeps valid labels, drops duplicate `flow_key`, replaces ±inf, fills structural NaNs with 0, builds `target` (0/1). | Mean/std can be undefined for tiny flows; zero is the natural fill. |
| `split_flow_dataset(df, ...)` | Stratified train / val / test by `attack_type` (default 70/15/15). | Stratify by attack type so rare attacks appear in every split. |
| `get_flow_feature_columns(df)` | Numeric columns minus IDs, IPs, labels, timestamps. | Prevents label leakage (e.g. using `source_file`). |
| `build_flow_preprocessor(scale=False)` | Sklearn pipeline: median impute (+ missing indicators) → drop constant columns → optional `RobustScaler`. | Trees (RF/XGB) do not need scaling; SVM does (`scale=True`). |
| `check_split_overlap(...)` | Counts shared `flow_key`s across splits. | Must be zero; otherwise evaluation is contaminated. |

### Script: `scripts/prepare_flow_dataset.py`

Loads a flow sample, cleans, splits, writes:
- `flow_train.csv`, `flow_validation.csv`, `flow_test.csv`
- `flow_split_metadata.json` (feature list, counts, overlap check)

**Example:**
```bash
python scripts/prepare_flow_dataset.py \
  --input-path data/samples/flow_sample_seed1.csv \
  --output-dir data/processed/phase3 \
  --seed 1
```

---

## 5. Packet ↔ flow linking

### File: `src/data/packet_flow_link.py`

This is the bridge the assignment asks for: every packet has a 5-tuple that maps to a CICFlowMeter `Flow ID`.

**Flow ID format:**
```text
{Src IP}-{Dst IP}-{Src Port}-{Dst Port}-{Protocol}
```
Protocol numbers: TCP = `6`, UDP = `17`.

| Function | What it does | Why |
|---|---|---|
| `packet_protocol(...)` | Maps packet `l4_tcp` / `l4_udp` flags → 6 / 17 / 0. | Packet CSVs use flags; flow CSVs use numeric protocol. |
| `build_flow_id(...)` | Builds one Flow ID string from 5-tuple. | Matches CICFlowMeter naming. |
| `add_packet_flow_ids(packet_df)` | Adds `flow_id_fwd` and `flow_id_rev` columns. | A packet in the reverse direction still belongs to the same conversation; CICFlowMeter may store either orientation. |
| `list_raw_flow_files(data_dir)` | Returns the six required raw flow CSV paths. | Ensures we search benign + all five attacks. |
| `load_flows_for_ids(data_dir, flow_ids)` | Chunk-scans raw flow files, keeps rows whose `Flow ID` is wanted, aggregates segments, dedupes. | Only loads flows we need (the Phase-2 alerts), not the whole dataset. |
| `resolve_packet_flow_ids(packet_df, available_ids)` | For each packet, prefer forward ID if it exists in loaded flows; else reverse. | ~95% of alerts match when both directions are tried. |

**Demo talking point:** “Packets don’t contain a Flow ID column. We reconstruct it from src/dst IP/port and L4 protocol, try both directions, then pull the matching CICFlowMeter rows and aggregate them.”

---

## 6. Two-stage cascade (main pipeline)

### Script: `scripts/run_two_stage_cascade.py`

This is the end-to-end runner. Read it top-to-bottom as the story of the system.

#### Helper functions

| Function | Role |
|---|---|
| `evaluate_binary(y_true, y_pred, scores, name)` | Computes accuracy, precision, recall, F1, FPR, FNR, confusion counts, optional ROC/PR-AUC. Same metrics table for Phase 2 alone and for the cascade. |
| `build_packet_features(df)` | Selects base + rolling packet features and engineers extras (payload ratio, DNS/HTTP/TLS indicators, burst ratios). Same feature philosophy as the Isolation Forest notebook. |
| `preprocess_packet_splits(...)` | Fit-on-train-only cleaning: zero-fill structural NaNs, drop constants, log1p skewed columns, drop highly correlated features (>0.98), median impute. |
| `select_threshold(y_val, scores, max_fpr=0.015)` | Sweeps high-score thresholds; keeps those with validation FPR ≤ 1.5%; picks max F1. Labels used **only** for threshold choice / evaluation, not for Isolation Forest fitting. |
| `train_phase2(packet_df)` | Stratified 60/20/20-ish split (train 60%, val 20%, test 20%), fit Isolation Forest on train features only, score val/test, freeze threshold. Returns model + predictions. |
| `train_phase3_xgboost(flow_dir)` | Loads Phase 3 train split; rebuilds XGBoost with `scale_pos_weight` (class imbalance) and best params from `reports/phase3/xgboost_best_parameters.json` if present. |
| `per_attack_detection(...)` | Detection rate per attack type on the packet test set. |

#### Isolation Forest scoring note

Sklearn’s `decision_function`: **higher = more normal**.  
We negate it (`-decision_function`) so **higher score = more anomalous**, which matches “alert if score ≥ threshold”.

#### Cascade decision rule (important)

For each **test** packet:

1. If Phase 2 does **not** alert → final = benign.  
2. If Phase 2 alerts **and** we find a matching flow → final = Phase 3 XGBoost prediction (attack if proba ≥ 0.5).  
3. If Phase 2 alerts **but** no flow is found → keep the Phase 2 alert (**fail-open**).

That means Phase 3 can only *remove* alerts (cut false positives) or confirm them — it never invents new alerts on packets Phase 2 ignored.

#### Outputs (`reports/cascade/`)

| File | Contents |
|---|---|
| `cascade_metrics.csv` | Phase 2 val/test + cascade test metrics |
| `cascade_per_attack.csv` | Per-attack detection: Phase 2 vs cascade |
| `cascade_summary.json` | Thresholds, timings, FP-reduction %, link rate |
| `cascade_test_predictions.csv` | Per-packet predictions for inspection |
| `cascade_models.joblib` | Saved IF + XGB pipeline for reuse |

**Run:**
```bash
python scripts/run_two_stage_cascade.py --seed 1
```

**Typical result to remember:** Phase 2 alone had many false positives; cascade cut FP by ~94% and raised precision a lot, with some recall cost (especially DNS Spoofing).

---

## 7. Phase 3 model notebooks

These train supervised classifiers on the **same** `data/processed/phase3/` splits so comparisons are fair.

| Notebook | Model | Notes |
|---|---|---|
| `notebooks/p3_random_forest.ipynb` | Random Forest | No scaling; `RandomizedSearchCV` + stratified 5-fold; refit on PR-AUC. |
| `notebooks/p3_xgboost.ipynb` | XGBoost | Uses `scale_pos_weight = n_benign / n_attack`; tree_method `hist`. Strongest Phase 3 model in our runs. |
| `notebooks/p3_svm.ipynb` | Linear SVM + calibration | Needs `RobustScaler`. `LinearSVC(dual=False)` because samples ≫ features; wrapped in `CalibratedClassifierCV` for probabilities. Kernel SVM would not scale to ~90k rows. |
| `notebooks/p3_two_stage_cascade.ipynb` | (no training) | Loads `reports/cascade/*` and plots Phase 2 vs cascade. |

**Common notebook pattern:**
1. Load train/val/test + metadata feature list  
2. Verify class counts and zero `flow_key` overlap  
3. Hyperparameter search on **train only**  
4. Evaluate on val then test at probability threshold 0.5  
5. Save metrics / feature importance / predictions under `reports/phase3/`

---

## 8. Other Phase 2 notebooks (packet unsupervised)

These live under `notebooks/` and explore alternative Phase 2 detectors on the packet sample:

| Notebook | Approach |
|---|---|
| `p2_isolation_forest.ipynb` | Isolation Forest (basis for the cascade’s Phase 2) |
| `p2_kmeans.ipynb` | K-Means distance-to-benign-cluster style scoring |
| `p2_autoencoders.ipynb` | PyTorch autoencoder reconstruction error (+ optional latent clustering) |
| `p1_packet_eda.ipynb` | Exploratory analysis that justifies preprocessing choices |

Shared discipline across Phase 2 notebooks:
- **Do not fit on labels**
- Use train / val / test
- Choose alert threshold on validation (often FPR-capped)
- Report precision, recall, F1, FPR, FNR, AUC, confusion matrix, per-attack rates

---

## 9. Utility scripts

| Script | Purpose |
|---|---|
| `scripts/inspect_dataset.py` | Explores raw CIC files (columns, sizes, candidate ID fields). Useful when first looking at the dataset. |
| `scripts/generate_random_packet_sample.py` | CLI → packet sampling |
| `scripts/generate_random_flow_sample.py` | CLI → flow sampling |
| `scripts/prepare_flow_dataset.py` | CLI → clean + split flows |
| `scripts/run_two_stage_cascade.py` | CLI → full two-stage system |

---

## 10. Data layout (what lives where)

```
data/
  raw/                  # CIC downloads (gitignored)
  samples/              # sampled packet/flow CSVs + metadata (gitignored)
  processed/phase3/     # train/val/test flow splits (gitignored)
reports/
  phase3/               # RF / XGB / SVM metrics (gitignored)
  cascade/              # two-stage outputs (gitignored)
src/data/               # reusable Python library code
scripts/                # command-line entry points
notebooks/              # experiments + figures
```

---

## 11. Demo checklist — questions you should be able to answer

1. **Why two stages?** Packet anomalies catch floods but raise FPs; flows add longer-horizon stats to reject benign lookalikes.  
2. **What is a Flow ID?** `IP-IP-port-port-protocol`, rebuilt from the packet 5-tuple.  
3. **Why forward and reverse IDs?** Flow meters may store either direction.  
4. **Does Phase 2 use labels while training?** No. Labels only for threshold selection and metrics.  
5. **Why `scale_pos_weight` in XGBoost?** Attacks are ~3% of flows; without it the model collapses toward “always benign.”  
6. **Why Linear SVM instead of RBF?** ~90k training rows; RBF SVM is too slow/memory-heavy.  
7. **What happens if a packet alert has no matching flow?** We keep the Phase 2 alert (fail-open).  
8. **What is FP reduction?** `(FP_phase2 − FP_cascade) / FP_phase2`.  
9. **Which attacks benefit most from packet-only detection?** DDoS/DoS HTTP Flood.  
10. **Which remain hard?** DNS Spoofing, Brute Force, XSS — they look closer to benign at packet level.

---

## 12. Suggested reading order

1. `src/data/sampling.py` → how the packet sample is built  
2. `src/data/flow_sampling.py` → segment aggregation (especially `aggregate_flow_segments`)  
3. `src/data/flow_preprocessing.py` → splits and leakage prevention  
4. `src/data/packet_flow_link.py` → the packet↔flow bridge  
5. `scripts/run_two_stage_cascade.py` → full system story  
6. One Phase 3 notebook (`p3_xgboost.ipynb`) → supervised training details  
7. `notebooks/p3_two_stage_cascade.ipynb` → results visualization  
