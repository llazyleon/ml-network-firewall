#!/usr/bin/env python3
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import pickle
import time
from pathlib import Path

# Columns that are non-predictive identifiers and risk data leakage if used as
# model features (a raw IP address or timestamp is effectively a row ID, not
# a generalizable traffic pattern). These are EXCLUDED entirely this time -
# not label-encoded, just dropped.
LEAKAGE_RISK_COLUMNS = ['flow_id', 'source_ip', 'destination_ip', 'timestamp']


class ModelTrainerV2:
    def __init__(self, data_path='data/processed/', model_path='data/models/', sample_size=0.2):
        self.data_path = Path(data_path)
        self.model_path = Path(model_path)
        self.sample_size = sample_size
        self.model_path.mkdir(exist_ok=True)

    def load_data(self):
        data_file = self.data_path / 'cicids2017_cleaned.csv'
        if not data_file.exists():
            print(f"ERROR: {data_file} not found!")
            return None
        print("Loading cleaned data...")
        df = pd.read_csv(data_file)
        print(f"✓ Loaded {len(df):,} rows")

        print(f"Using {100*self.sample_size:.0f}% sample to reduce memory usage...")
        df = df.sample(frac=self.sample_size, random_state=42)
        print(f"✓ Sample size: {len(df):,} rows\n")

        return df

    def prepare_features_labels(self, df):
        print("Preparing features and labels...")
        target_col = None
        for col in ['label', 'Label', 'class', 'Class']:
            if col in df.columns:
                target_col = col
                break
        if target_col is None:
            print("ERROR: Could not find label column")
            return None, None

        y = df[target_col].apply(lambda x: 0 if str(x).upper() == 'BENIGN' else 1)

        # Drop the label AND the leakage-risk identifier columns this time
        drop_cols = [target_col] + [c for c in LEAKAGE_RISK_COLUMNS if c in df.columns]
        X = df.drop(columns=drop_cols)
        print(f"  Dropped identifier columns (leakage risk): {[c for c in LEAKAGE_RISK_COLUMNS if c in df.columns]}")

        # Any remaining object-dtype columns (shouldn't be many) still get
        # label-encoded, but the high-risk identifiers are already gone.
        from sklearn.preprocessing import LabelEncoder
        remaining_object_cols = list(X.select_dtypes(include=['object']).columns)
        if remaining_object_cols:
            print(f"  Label-encoding remaining categorical columns: {remaining_object_cols}")
            for col in remaining_object_cols:
                X[col] = LabelEncoder().fit_transform(X[col].astype(str))

        benign = sum(y == 0)
        attack = sum(y == 1)
        print(f"  Benign: {benign:,}")
        print(f"  Attack: {attack:,}")
        print(f"  Total features: {X.shape[1]}\n")

        return X, y

    def train_model(self, X, y):
        print(f"{'='*60}")
        print("Training Random Forest (corrected feature set)")
        print(f"{'='*60}\n")

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        print(f"Training set: {len(X_train):,} rows")
        print(f"Test set: {len(X_test):,} rows\n")

        print("Training (this may take a few minutes)...")
        start = time.time()

        rf = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            min_samples_split=5,
            n_jobs=-1,
            random_state=42,
            verbose=1
        )
        rf.fit(X_train, y_train)

        elapsed = time.time() - start
        print(f"\n✓ Training complete in {elapsed/60:.1f} minutes\n")

        print(f"{'='*60}")
        print("Evaluation (corrected, leakage-free feature set)")
        print(f"{'='*60}\n")

        y_pred = rf.predict(X_test)
        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred)
        recall = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)

        print(f"Accuracy:  {acc:.4f} ({100*acc:.2f}%)")
        print(f"Precision: {prec:.4f}")
        print(f"Recall:    {recall:.4f}")
        print(f"F1-Score:  {f1:.4f}\n")

        importance_df = pd.DataFrame({
            'feature': X_test.columns,
            'importance': rf.feature_importances_
        }).sort_values('importance', ascending=False)

        print("Top 10 Important Features (no identifier columns this time):")
        for idx, row in importance_df.head(10).iterrows():
            print(f"  {row['feature']}: {row['importance']:.4f}")

        return rf

    def save_model(self, model):
        output_path = self.model_path / 'rf_model.pkl'
        with open(output_path, 'wb') as f:
            pickle.dump(model, f)

        size_mb = output_path.stat().st_size / (1024 * 1024)
        print(f"\n✓ Model saved: {output_path}")
        print(f"  Size: {size_mb:.1f} MB\n")

    def run(self):
        df = self.load_data()
        if df is None:
            return

        X, y = self.prepare_features_labels(df)
        if X is None:
            return

        model = self.train_model(X, y)
        self.save_model(model)

        print(f"{'='*60}")
        print("✓ Retraining complete (identifier columns excluded)")
        print(f"{'='*60}\n")


if __name__ == '__main__':
    trainer = ModelTrainerV2(sample_size=0.2)
    trainer.run()
