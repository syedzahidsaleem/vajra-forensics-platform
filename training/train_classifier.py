"""
Model Training & ONNX Export Pipeline (§33).

Trains a CPU-only Gradient Boosted Decision Tree (GBDT) on the 280-dimensional feature set:
- Evaluates Precision, Recall, F1, and Confusion Matrix across train/val/test splits.
- Computes feature importances for explainable forensic provenance (§33, §31).
- Exports:
  1. `ml-models/file_type_classifier.onnx` (Standard ONNX format via skl2onnx / onnx)
  2. `ml-models/file_type_classifier_trees.json` (Native tree weights for deterministic zero-dependency inference)
  3. `ml-models/model_metadata.json` (Evaluation metrics, feature names, class map)
"""

import json
import os
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, f1_score, precision_score, recall_score
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType
import onnx

from dataset_generator import generate_dataset, export_parity_fixtures, CLASSES
from feature_extractor import FEATURE_NAMES, NUM_FEATURES


def export_trees_to_json(model, feature_names, class_names, output_path):
    """Exports tree structure to JSON for native pure-Rust inference."""
    estimators = model.estimators_ # shape: (n_estimators, n_classes)
    n_estimators = model.n_estimators_
    n_classes = len(class_names)

    trees_data = {
        "n_classes": n_classes,
        "n_estimators": n_estimators,
        "n_features": len(feature_names),
        "class_names": class_names,
        "feature_names": feature_names,
        "feature_importances": [float(x) for x in model.feature_importances_],
        "init_prior": [float(p) for p in getattr(model.init_, "class_prior_", [1.0 / n_classes] * n_classes)],
        "trees": []
    }

    for est_idx in range(n_estimators):
        class_trees = []
        for class_idx in range(n_classes):
            tree_obj = estimators[est_idx, class_idx].tree_
            tree_dict = {
                "node_count": int(tree_obj.node_count),
                "children_left": [int(x) for x in tree_obj.children_left],
                "children_right": [int(x) for x in tree_obj.children_right],
                "feature": [int(x) for x in tree_obj.feature],
                "threshold": [float(x) for x in tree_obj.threshold],
                "value": [float(x[0, 0]) for x in tree_obj.value],
            }
            class_trees.append(tree_dict)
        trees_data["trees"].append(class_trees)

    with open(output_path, "w") as f:
        json.dump(trees_data, f, indent=2)
    print(f"Exported native tree ensemble to {output_path}")


def train_and_export():
    print("=" * 70)
    print("      VAJRA ML LAYER — OFFLINE MODEL TRAINING PIPELINE (§33)")
    print("=" * 70)

    # 1. Generate Dataset
    print("\n[STEP 1] Generating synthetic ground-truth dataset (1,800 samples)...")
    X, y, metadata = generate_dataset(samples_per_class=300)
    export_parity_fixtures()

    # 2. Train/Test Split (70/30 stratified)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.30, random_state=42, stratify=y
    )

    print(f"Dataset split: {len(X_train)} training samples, {len(X_test)} test samples.")

    # 3. Train Gradient Boosted Decision Tree (CPU-only)
    print("\n[STEP 2] Training Gradient Boosted Decision Tree classifier (CPU-only)...")
    model = GradientBoostingClassifier(
        n_estimators=60,
        learning_rate=0.1,
        max_depth=4,
        min_samples_split=5,
        min_samples_leaf=2,
        subsample=0.85,
        random_state=42,
    )

    model.fit(X_train, y_train)

    # 4. Model Evaluation
    print("\n[STEP 3] Evaluating model performance on held-out test set...")
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)

    prec_macro = precision_score(y_test, y_pred, average="macro")
    rec_macro = recall_score(y_test, y_pred, average="macro")
    f1_macro = f1_score(y_test, y_pred, average="macro")

    print("\n--- TEST SET CLASSIFICATION REPORT ---")
    report_text = classification_report(y_test, y_pred, target_names=CLASSES, digits=4)
    print(report_text)

    cm = confusion_matrix(y_test, y_pred)
    print("--- CONFUSION MATRIX ---")
    print(f"{'':>10}" + "".join([f"{c:>10}" for c in CLASSES]))
    for idx, row in enumerate(cm):
        print(f"{CLASSES[idx]:>10}" + "".join([f"{val:>10}" for val in row]))

    # Top 10 Feature Importances
    importances = model.feature_importances_
    top_indices = np.argsort(importances)[::-1][:15]
    print("\n--- TOP 15 INFORMATIVE FEATURES (EXPLAINABILITY) ---")
    top_features = []
    for rank, idx in enumerate(top_indices, 1):
        feat_name = FEATURE_NAMES[idx]
        imp_val = float(importances[idx])
        top_features.append({"rank": rank, "index": int(idx), "name": feat_name, "importance": imp_val})
        print(f"  {rank:2d}. {feat_name:<30} (importance: {imp_val:.4f})")

    # 5. Export ONNX & Native Artifacts
    print("\n[STEP 4] Exporting ONNX and native tree model artifacts to ml-models/...")
    os.makedirs("ml-models", exist_ok=True)

    # Export ONNX via skl2onnx
    initial_type = [("float_input", FloatTensorType([None, NUM_FEATURES]))]
    onnx_model = convert_sklearn(
        model,
        initial_types=initial_type,
        target_opset=12,
        options={id(model): {"zipmap": False}}
    )
    onnx_path = "ml-models/file_type_classifier.onnx"
    with open(onnx_path, "wb") as f:
        f.write(onnx_model.SerializeToString())
    print(f"Exported ONNX model to {onnx_path} ({os.path.getsize(onnx_path)} bytes)")

    # Export Native Tree Weights
    trees_path = "ml-models/file_type_classifier_trees.json"
    export_trees_to_json(model, FEATURE_NAMES, CLASSES, trees_path)

    # Export Metadata
    metadata_path = "ml-models/model_metadata.json"
    meta_dict = {
        "model_type": "GradientBoostingClassifier",
        "n_estimators": 60,
        "max_depth": 4,
        "n_features": NUM_FEATURES,
        "classes": CLASSES,
        "metrics": {
            "macro_precision": float(prec_macro),
            "macro_recall": float(rec_macro),
            "macro_f1": float(f1_macro),
            "test_sample_count": len(y_test),
        },
        "top_features": top_features,
    }
    with open(metadata_path, "w") as f:
        json.dump(meta_dict, f, indent=2)
    print(f"Exported model metadata to {metadata_path}")

    print("\n[+] Training & Export Pipeline Complete!")
    return meta_dict


if __name__ == "__main__":
    train_and_export()
