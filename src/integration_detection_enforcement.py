#!/usr/bin/env python3
import sys, time, logging
from datetime import datetime
import requests
import pandas as pd
import numpy as np

sys.path.insert(0, '.')

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')
logger = logging.getLogger(__name__)

DASHBOARD_URL = "http://localhost:8000"
DATA_PATH = "data/processed/cicids2017_cleaned.csv"
NUM_FLOWS_TO_REPLAY = 300          # how many real flows to replay this run
RUN_SECONDS = 60                   # stop after this long regardless
METADATA_COLS = ['flow_id', 'source_ip', 'source_port',
                  'destination_ip', 'destination_port', 'protocol', 'timestamp']

print("\n" + "=" * 70)
print("INTEGRATED ML FIREWALL - PHASE 3 + PHASE 4 (REAL CLASSIFIER)")
print("=" * 70 + "\n")

try:
    import importlib.util

    # Load Phase 3 (Detection)
    spec = importlib.util.spec_from_file_location("classifier", "src/09_classifier.py")
    clf_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(clf_module)
    Classifier = clf_module.FlowClassifier

    logger.info("Initializing Phase 3 (Detection)...")
    classifier = Classifier()
    logger.info("Phase 3 ready")

    # Load Phase 4 (Enforcement)
    spec_enforce = importlib.util.spec_from_file_location(
        "firewall_enforcement", "src/11_firewall_enforcement_advanced.py")
    enforce_module = importlib.util.module_from_spec(spec_enforce)
    spec_enforce.loader.exec_module(enforce_module)
    AdvancedFirewallEnforcer = enforce_module.AdvancedFirewallEnforcer
    enforcer = AdvancedFirewallEnforcer()
    logger.info("Phase 4 ready")

    # --- Load a random sample of real flows to replay ---
    logger.info(f"Loading {NUM_FLOWS_TO_REPLAY} real flows from {DATA_PATH} ...")
    full_df = pd.read_csv(DATA_PATH)
    sample_df = full_df.sample(n=min(NUM_FLOWS_TO_REPLAY, len(full_df))).reset_index(drop=True)
    feature_cols = [c for c in sample_df.columns if c not in METADATA_COLS + ['label']]
    logger.info(f"Loaded {len(sample_df)} flows, {len(feature_cols)} features per flow")

    def push_to_dashboard(is_attack, source_ip=None, attack_type=None, confidence=None):
        try:
            if is_attack:
                requests.post(f"{DASHBOARD_URL}/api/alert", json={
                    "source_ip": source_ip,
                    "attack_type": attack_type,
                    "confidence": confidence,
                }, timeout=1)
            else:
                requests.post(f"{DASHBOARD_URL}/api/benign", timeout=1)
        except requests.exceptions.RequestException:
            logger.warning("Dashboard not reachable - is dashboard_phase5.py running?")

    print("\n" + "=" * 70)
    print(f"REPLAYING {len(sample_df)} REAL FLOWS THROUGH TRAINED CLASSIFIER")
    print("=" * 70 + "\n")

    stats = {
        'total_flows': 0,
        'benign': 0,
        'attacks': 0,
        'blocked_ips': set(),
        'correct': 0,   # predicted attack-status matches true label
    }

    start_time = time.time()

    for i, row in sample_df.iterrows():
        if time.time() - start_time > RUN_SECONDS:
            logger.info("Time limit reached, stopping replay")
            break

        features = row[feature_cols].to_numpy(dtype=float)
        true_label = str(row['label'])
        source_ip = str(row['source_ip'])

        pred, confidence = classifier.predict(features)

        # Normalize prediction into is_attack / attack_type, handling either
        # a string label (e.g. "DDoS") or a numeric class output.
        if isinstance(pred, (str, np.str_)):
            is_attack = pred.upper() != 'BENIGN'
            attack_type = pred if is_attack else None
        else:
            is_attack = int(pred) != 0
            attack_type = f"Class_{int(pred)}" if is_attack else None

        stats['total_flows'] += 1
        true_is_attack = true_label.upper() != 'BENIGN'
        if is_attack == true_is_attack:
            stats['correct'] += 1

        if is_attack:
            stats['attacks'] += 1
            enforcer.block_attack(
                source_ip=source_ip,
                confidence=confidence,
                flow_id=f'flow_{stats["total_flows"]}',
                attack_type=attack_type,
                ttl_hours=24
            )
            stats['blocked_ips'].add(source_ip)
            push_to_dashboard(True, source_ip=source_ip, attack_type=attack_type, confidence=confidence)
            print(f"  [ATTACK]  {source_ip:15s} true={true_label:12s} pred={attack_type:12s} conf={confidence:.3f}")
        else:
            stats['benign'] += 1
            push_to_dashboard(False)

        time.sleep(0.05)

    print("\n" + "=" * 70)
    print("FIREWALL STATISTICS (REAL CLASSIFIER)")
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
