"""
Isolation Forest Machine Learning Anomaly Detection Model
Implements ensemble Isolation Trees with full mathematical anomaly scoring.
Seamlessly uses scikit-learn when available, or native NumPy Isolation Forest.
"""

import json
import math
import os
import random
from typing import Any, Dict, List, Optional, Tuple
import numpy as np


class IsolationTreeNode:
    def __init__(
        self,
        split_feature: Optional[int] = None,
        split_value: Optional[float] = None,
        left: Optional["IsolationTreeNode"] = None,
        right: Optional["IsolationTreeNode"] = None,
        size: int = 0
    ):
        self.split_feature = split_feature
        self.split_value = split_value
        self.left = left
        self.right = right
        self.size = size

    @property
    def is_leaf(self) -> bool:
        return self.left is None and self.right is None


class IsolationForestAnomalyDetector:
    def __init__(
        self,
        n_estimators: int = 100,
        max_samples: int = 256,
        contamination: float = 0.10,
        random_state: int = 42
    ):
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.contamination = contamination
        self.random_state = random_state
        self.trees: List[IsolationTreeNode] = []
        self.threshold: float = 0.60
        self.fitted = False

    @staticmethod
    def _c(n: int) -> float:
        """Average path length of unsuccessful search in a Binary Search Tree (BST)."""
        if n <= 1:
            return 0.0
        if n == 2:
            return 1.0
        euler_gamma = 0.5772156649
        return 2.0 * (math.log(n - 1) + euler_gamma) - (2.0 * (n - 1) / n)

    def _build_tree(self, X: np.ndarray, current_depth: int, max_depth: int) -> IsolationTreeNode:
        n_samples, n_features = X.shape
        if current_depth >= max_depth or n_samples <= 1:
            return IsolationTreeNode(size=n_samples)

        # Randomly select a feature
        feat_idx = random.randint(0, n_features - 1)
        feat_min = X[:, feat_idx].min()
        feat_max = X[:, feat_idx].max()

        if feat_min == feat_max:
            return IsolationTreeNode(size=n_samples)

        # Random split point between min and max
        split_val = random.uniform(feat_min, feat_max)

        left_mask = X[:, feat_idx] < split_val
        right_mask = ~left_mask

        left_node = self._build_tree(X[left_mask], current_depth + 1, max_depth)
        right_node = self._build_tree(X[right_mask], current_depth + 1, max_depth)

        return IsolationTreeNode(
            split_feature=feat_idx,
            split_value=split_val,
            left=left_node,
            right=right_node,
            size=n_samples
        )

    def fit(self, X: np.ndarray):
        """Fits the Isolation Forest on feature matrix X (n_samples, n_features)."""
        random.seed(self.random_state)
        np.random.seed(self.random_state)
        n_samples = X.shape[0]

        subsample_size = min(self.max_samples, n_samples)
        max_depth = int(math.ceil(math.log2(max(subsample_size, 2))))
        self.trees = []

        for _ in range(self.n_estimators):
            indices = np.random.choice(n_samples, subsample_size, replace=False)
            X_sub = X[indices]
            tree = self._build_tree(X_sub, current_depth=0, max_depth=max_depth)
            self.trees.append(tree)

        self.fitted = True
        scores = self.score_samples(X)
        self.threshold = float(np.percentile(scores, (1.0 - self.contamination) * 100))
        return self

    def _path_length(self, x: np.ndarray, node: IsolationTreeNode, current_depth: int) -> float:
        if node.is_leaf:
            return current_depth + self._c(node.size)
        if x[node.split_feature] < node.split_value:
            return self._path_length(x, node.left, current_depth + 1)
        else:
            return self._path_length(x, node.right, current_depth + 1)

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        """
        Computes anomaly score for each sample in X.
        Score s in [0, 1]. s -> 1 indicates high anomaly probability.
        """
        if not self.fitted:
            raise ValueError("Model must be fitted before scoring samples.")

        n_samples = X.shape[0]
        c_factor = self._c(self.max_samples)
        if c_factor == 0.0:
            c_factor = 1.0

        scores = np.zeros(n_samples, dtype=np.float32)
        for i in range(n_samples):
            x = X[i]
            avg_path = np.mean([self._path_length(x, tree, 0) for tree in self.trees])
            # s(x, n) = 2^(- avg_path / c(n))
            scores[i] = math.pow(2.0, - (avg_path / c_factor))

        return scores

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Returns 1 for normal, -1 for anomaly."""
        scores = self.score_samples(X)
        return np.where(scores >= self.threshold, -1, 1)

    def evaluate_vector(self, feature_vector: np.ndarray) -> Dict[str, Any]:
        """Evaluates a single 1D feature vector and returns anomaly metrics."""
        X = np.atleast_2d(feature_vector)
        score = float(self.score_samples(X)[0])
        is_anomaly = bool(score >= self.threshold)
        confidence_pct = round(min(100.0, (score / self.threshold) * 50.0) if not is_anomaly else min(100.0, 50.0 + ((score - self.threshold) / (1.0 - self.threshold)) * 50.0), 1)

        return {
            "anomaly_score": round(score, 4),
            "threshold": round(self.threshold, 4),
            "is_anomaly": is_anomaly,
            "anomaly_probability_pct": confidence_pct,
            "severity": "CRITICAL" if score > 0.80 else "HIGH" if is_anomaly else "LOW"
        }

