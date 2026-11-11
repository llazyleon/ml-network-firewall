#!/usr/bin/env python3
import sys, time, logging
import requests
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

sys.path.insert(0, '.')

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')
logger = logging.getLogger(__name__)

DASHBOARD_URL = "http://localhost:8000"
DATA_PATH = "data/processed/cicids2017_cleaned.csv"
NUM_FLOWS_TO_REPLAY = 300
RUN_SECONDS = 60

print("\n" + "=" * 70)
print("INTEGRATED ML FIREWALL - PHASE 3 + PHASE 4 (REAL CLASSIFIER)")
print("=" * 70 + "\n")

try:
    import importlib.util

    spec = importlib.util.spec_from_file_location("classifier", "src/09_classifier.py")
    clf_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(clf_module)
    Classifier = clf_module.FlowClassifier

    logger.info("Initializing Phase 3 (Detection)...")
    classifier = Classifier()
    logger.info("Phase 3 ready")

    spec_enforce = importlib.util.spec_from_file_location(
        "firewall_enforcement", "src/11_firewall_enforcement_advanced.py")
    enforce_module = importlib.util.module_from_spec(spec_enforce)
    spec_enforce.loader.exec_module(enforce_module)
    AdvancedFirewallEnforcer = enforce_module.AdvancedFirewallEnforcer
    enforcer = AdvancedFirewallEnforcer()
    logger.info("Phase 4 ready")

    # --- Replicate Phase 2's exact data prep so features match what the model was trained on ---
    logger.info("Loading and preparing data (matching Phase 2 training pipeline)...")
    df = pd.read_csv(DATA_PATH)
    df = df.sample(frac=0.2, random_state=42)  # same sampling as 02_model_trainer.py

    y = df['label'].apply(lambda x: 0 if str(x).upper() == 'BENIGN' else 1)
    true_labels = df['label']            # keep real attack-type strings for display only
    raw_source_ips = df['source_ip']     # keep real (unencoded) IPs for display/blocking only

    X = df.drop('label', axis=1)
    for col in X.select_dtypes(include=['object']).columns:
        X[col] = LabelEncoder().fit_transform(X[col].astype(str))

    # Same split as training - the test portion is genuinely held-out data
    X_train, X_test, y_train, y_test, true_train, true_test, ip_train, ip_test = train_test_split(
        X, y, true_labels, raw_source_ips, test_size=0.2, random_state=42, stratify=y
    )
    logger.info(f"Held-out test set: {len(X_test)} flows, {X_test.shape[1]} features/flow")

    # Sample flows from the held-out test set to replay
    n = min(NUM_FLOWS_TO_REPLAY, len(X_test))
    sample_idx = np.random.choice(X_test.index, size=n, replace=False)

    def push_to_dashboard(is_attack, source_ip=None, attack_type=None, confidence=None):
        try:
            if is_attack:
                requests.post(f"{DASHBOARD_URL}/api/alert", json={
                    "source_ip": source_ip, "attack_type": attack_type, "confidence": confidence,
                }, timeout=1)
            else:
                requests.post(f"{DASHBOARD_URL}/api/benign", timeout=1)
        except requests.exceptions.RequestException:
            logger.warning("Dashboard not reachable - is dashboard_phase5.py running?")

    print("\n" + "=" * 70)
    print(f"REPLAYING {n} REAL (HELD-OUT) FLOWS THROUGH TRAINED CLASSIFIER")
    print("=" * 70 + "\n")

    stats = {'total_flows': 0, 'benign': 0, 'attacks': 0, 'blocked_ips': set(), 'correct': 0}
    start_time = time.time()

    for idx in sample_idx:
        if time.time() - start_time > RUN_SECONDS:
            logger.info("Time limit reached, stopping replay")
            break

        features = X_test.loc[idx].to_numpy(dtype=float)
        true_binary = int(y_test.loc[idx])
        true_type = str(true_test.loc[idx])
        source_ip = str(ip_test.loc[idx])

        pred, confidence = classifier.predict(features)
        is_attack = int(pred) == 1

        stats['total_flows'] += 1
        if is_attack == bool(true_binary):
            stats['correct'] += 1

        if is_attack:
            stats['attacks'] += 1
            enforcer.block_attack(
                source_ip=source_ip, confidence=confidence,
                flow_id=f'flow_{stats["total_flows"]}',
                attack_type=true_type,   # real ground-truth type, shown for context (model itself is binary)
                ttl_hours=24
            )
            stats['blocked_ips'].add(source_ip)
            push_to_dashboard(True, source_ip=source_ip, attack_type=true_type, confidence=confidence)
            print(f"  [ATTACK]  {source_ip:15s} true_type={true_type:20s} model_pred=ATTACK conf={confidence:.3f}")
        else:
            stats['benign'] += 1
            push_to_dashboard(False)

        time.sleep(0.05)

    print("\n" + "=" * 70)
    print("FIREWALL STATISTICS (REAL CLASSIFIER, HELD-OUT DATA)")
    print("=" * 70)
    print(f"Total flows processed:  {stats['total_flows']}")
    print(f"Benign flows:           {stats['benign']}")
    print(f"Attack flows detected:  {stats['attacks']}")
    print(f"Detection rate:         {(stats['attacks']/max(stats['total_flows'],1))*100:.1f}%")
    print(f"Accuracy vs true label: {(stats['correct']/max(stats['total_flows'],1))*100:.2f}%")

    print("\n" + "=" * 70)
    print("ENFORCEMENT STATISTICS (Phase 4)")
    print("=" * 70)
    status = enforcer.get_status()
    print(f"Unique IPs blocked:     {len(status['active_blocks'])}")
    print(f"Total enforcement actions: {status['metrics']['blocks']}")

    print("\n" + "=" * 70)
    print("✅ REPLAY COMPLETE (real classifier + real dashboard integration)")
    print("=" * 70 + "\n")

    enforcer.export_report('firewall_report.json')
    print("Report saved to: firewall_report.json\n")

except Exception as e:
    logger.error(f"Error: {e}")
    import traceback
    traceback.print_exc()
