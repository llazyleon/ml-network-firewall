#!/usr/bin/env python3
import pandas as pd
import numpy as np
from pathlib import Path
import glob

RAW_DIR = Path("data/raw")
OUTPUT_PATH = Path("data/processed/cicids2017_cleaned.csv")

print("\n" + "=" * 70)
print("PHASE 1: DATA CLEANING - Rebuilding cicids2017_cleaned.csv")
print("=" * 70 + "\n")

OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

raw_files = sorted(glob.glob(str(RAW_DIR / "*.csv")))
if not raw_files:
    print(f"ERROR: No CSV files found in {RAW_DIR}/")
    exit(1)

print(f"Found {len(raw_files)} raw files:")
for f in raw_files:
    print(f"  - {Path(f).name}")
print()

dataframes = []
for f in raw_files:
    print(f"Reading {Path(f).name} ...", end=" ")
    try:
        df = pd.read_csv(f, encoding='utf-8', low_memory=False)
    except UnicodeDecodeError:
        # A couple of the original CICIDS2017 mirrors have one file with
        # non-UTF-8 characters (typically Wednesday's file) - fall back cleanly.
        print("(retrying with latin-1 encoding)", end=" ")
        df = pd.read_csv(f, encoding='latin1', low_memory=False)

    # Normalize column names: strip whitespace (raw CICFlowMeter headers have
    # leading spaces on almost every column), lowercase, spaces -> underscores.
    # Note: the raw headers contain a genuine duplicate "Fwd Header Length"
    # column; pandas automatically disambiguates the second occurrence as
    # "Fwd Header Length.1" at read time, which this renaming preserves as
    # "fwd_header_length.1" - matching the original cleaned dataset exactly.
    df.columns = df.columns.str.strip().str.lower().str.replace(' ', '_')

    print(f"{len(df):,} rows")
    dataframes.append(df)

print(f"\nCombining {len(dataframes)} files...")
combined = pd.concat(dataframes, ignore_index=True)
print(f"✓ Combined: {len(combined):,} rows, {combined.shape[1]} columns\n")

# Ensure the label column is named exactly 'label'
label_col = None
for candidate in ['label', 'Label', ' Label']:
    if candidate in combined.columns:
        label_col = candidate
        break
if label_col is None:
    # last resort - find any column literally containing 'label'
    matches = [c for c in combined.columns if 'label' in c.lower()]
    if matches:
        label_col = matches[0]
if label_col and label_col != 'label':
    combined = combined.rename(columns={label_col: 'label'})

print("Label distribution before cleaning:")
print(combined['label'].value_counts())
print()

# Replace infinite values (common in flow_bytes_s / flow_packets_s when flow
# duration is zero) with NaN, then drop any row containing NaN in any column.
print("Cleaning infinite and missing values...")
before = len(combined)
combined = combined.replace([np.inf, -np.inf], np.nan)
combined = combined.dropna()
after = len(combined)
print(f"✓ Dropped {before - after:,} rows with infinite/missing values")
print(f"✓ Remaining: {after:,} rows\n")

combined = combined.reset_index(drop=True)

print("Final label distribution:")
print(combined['label'].value_counts())
print()

print(f"Saving to {OUTPUT_PATH} ...")
combined.to_csv(OUTPUT_PATH, index=False)
size_mb = OUTPUT_PATH.stat().st_size / (1024 * 1024)
print(f"✓ Saved: {OUTPUT_PATH} ({size_mb:.1f} MB)\n")

print("=" * 70)
print("✓ PHASE 1 COMPLETE - cicids2017_cleaned.csv regenerated")
print("=" * 70 + "\n")
