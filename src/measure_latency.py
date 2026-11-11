#!/usr/bin/env python3
import sys
import time
import numpy as np
import pandas as pd

sys.path.insert(0, '.')
import importlib.util

spec = importlib.util.spec_from_file_location("classifier", "src/09_classifier.py")
clf_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(clf_module)
Classifier = clf_module.FlowClassifier

print("Loading classifier...")
classifier = Classifier()

print("Loading sample flows for timing...")
df = pd.read_csv("data/processed/cicids2017_cleaned.csv")
df = df.drop('label', axis=1)

N = 1000
sample = df.sample(n=N, random_state=42)

print(f"\nTiming {N} individual predict() calls...\n")

latencies_ms = []
for _, row in sample.iterrows():
    features = row.to_numpy(dtype=float)
    start = time.perf_counter()
    classifier.predict(features)
    elapsed_ms = (time.perf_counter() - start) * 1000
    latencies_ms.append(elapsed_ms)

latencies_ms = np.array(latencies_ms)

print("=" * 50)
print("INFERENCE LATENCY RESULTS")
print("=" * 50)
print(f"Samples:        {N}")
print(f"Mean latency:   {latencies_ms.mean():.3f} ms")
print(f"Median latency: {np.median(latencies_ms):.3f} ms")
print(f"95th pctile:    {np.percentile(latencies_ms, 95):.3f} ms")
print(f"99th pctile:    {np.percentile(latencies_ms, 99):.3f} ms")
print(f"Max latency:    {latencies_ms.max():.3f} ms")
print(f"Min latency:    {latencies_ms.min():.3f} ms")
print("=" * 50)
