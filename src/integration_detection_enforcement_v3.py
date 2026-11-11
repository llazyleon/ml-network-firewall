#!/usr/bin/env python3
import sys, time, logging
import requests
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split

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

    logger.info("Loading and preparing data...")
    df = pd.read_csv(DATA_PATH)
    df = df.sample(frac=0.2, random_state=42)

    y = df['label'].apply(lambda x: 0 if str(x).upper() == 'BENIGN' else 1)
    true_labels = df['label']

    X = df.drop('label', axis=1)
    # NOTE: this dataset variant contains no identifier columns (flow_id,
    # source_ip, destination_ip, timestamp) at all - it was never possible
    # for this pipeline to leak on them. All remaining columns are genuine
    # flow-behavioural features (destination_port, protocol, byte counts,
    # timing statistics, etc.) and are used directly with no encoding needed.

    X_train, X_test, y_train, y_test, true_train, true_test = train_test_split(
        X, y, true_labels, test_size=0.2, random_state=42, stratify=y
    )
    logger.info(f"Held-out test set: {len(X_test)} flows, {X_test.shape[1]} features/flow")

    n = min(NUM_FLOWS_TO_REPLAY, len(X_test))
    sample_idx = np.random.choice(X_test.index, size=n, replace=False)

    def synthetic_ip(seed):
        # Deterministic, clearly-labelled placeholder IP for demonstration
        # purposes only - this dataset variant does not include real source
        # IP addresses. NOT a claim about the actual attacker's address.
        rng = np.random.RandomState(seed)
        return f"10.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,255)}"

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
    print("(source IPs below are SYNTHETIC placeholders - this dataset")
    print(" variant contains no real IP addresses)")
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
        source_ip = synthetic_ip(idx)

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
                attack_type=true_type,
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
