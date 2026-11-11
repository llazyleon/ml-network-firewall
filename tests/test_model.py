#!/usr/bin/env python3
"""
Sanity and regression tests for the trained classifier (data/models/rf_model.pkl).

M01 guards against the data-leakage problem found during development: the
model must not use any identifier field (flow ID, IP addresses, timestamp).
The other tests check the model's interface as the detection engine uses it.

Run from the project root:
  venv/bin/python3 -m pytest tests/test_model.py -v
"""
import pickle
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

MODEL_PATH = Path("data/models/rf_model.pkl")
IDENTIFIER_HINTS = ("flow_id", "flowid", "source_ip", "src_ip", "destination_ip",
                    "dst_ip", "timestamp")

pytestmark = pytest.mark.skipif(not MODEL_PATH.exists(), reason=f"{MODEL_PATH} not found")


@pytest.fixture(scope="module")
def model():
    with open(MODEL_PATH, "rb") as f:
        m = pickle.load(f)
    m.verbose = 0
    return m


@pytest.fixture(scope="module")
def zero_input(model):
    cols = getattr(model, "feature_names_in_", None)
    n = model.n_features_in_
    data = np.zeros((1, n))
    return pd.DataFrame(data, columns=cols) if cols is not None else data


def test_M01_no_identifier_features(model):
    names = [str(c).lower().replace(" ", "_") for c in getattr(model, "feature_names_in_", [])]
    assert names, "model has no stored feature names - cannot check for identifiers"
    leaked = [n for n in names if any(h in n for h in IDENTIFIER_HINTS)]
    assert leaked == [], f"identifier fields used as features: {leaked}"


def test_M02_expected_feature_count(model):
    assert model.n_features_in_ == 78


def test_M03_binary_output(model, zero_input):
    assert set(model.classes_) == {0, 1}
    assert model.predict(zero_input)[0] in (0, 1)


def test_M04_confidence_is_a_probability(model, zero_input):
    proba = model.predict_proba(zero_input)[0]
    assert np.all((proba >= 0) & (proba <= 1))
    assert abs(proba.sum() - 1.0) < 1e-9


def test_M05_prediction_is_deterministic(model, zero_input):
    first = model.predict_proba(zero_input)
    for _ in range(5):
        assert np.array_equal(model.predict_proba(zero_input), first)


def test_M06_configuration_matches_thesis(model):
    assert model.n_estimators == 100
    assert model.max_depth == 20
