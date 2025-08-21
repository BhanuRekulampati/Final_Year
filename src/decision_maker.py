import numpy as np


class DecisionMaker:
	def __init__(self):
		# Lightweight, NumPy-only scorer to avoid heavy dependencies
		self.feature_means = None
		self.feature_stds = None
		self.weights = None
		self.bias = 0.0

	def _standardize(self, X: np.ndarray) -> np.ndarray:
		if self.feature_means is None or self.feature_stds is None:
			return X
		return (X - self.feature_means) / self.feature_stds

	def train(self, features: np.ndarray, decisions: np.ndarray) -> None:
		"""
		Train a simple linear scorer using least squares on standardized features.
		features: shape (n_samples, n_features)
		decisions: shape (n_samples,), values in {0,1}
		"""
		features = np.asarray(features, dtype=float)
		decisions = np.asarray(decisions, dtype=float)

		# Standardize features for stability
		self.feature_means = features.mean(axis=0)
		self.feature_stds = features.std(axis=0)
		self.feature_stds[self.feature_stds == 0.0] = 1.0
		Xz = self._standardize(features)

		# Map labels {0,1} -> {-1, +1} for regression target
		y = decisions * 2.0 - 1.0

		# Append bias column and solve least squares
		X_design = np.hstack([Xz, np.ones((Xz.shape[0], 1))])
		coef, *_ = np.linalg.lstsq(X_design, y, rcond=None)
		self.weights = coef[:-1]
		self.bias = float(coef[-1])

	def make_decision(self, input_features: np.ndarray) -> dict:
		"""
		Score input and output a binary decision with confidence.
		input_features: shape (n_features,)
		"""
		x = np.asarray(input_features, dtype=float).reshape(1, -1)
		xz = self._standardize(x)
		score = float(np.dot(xz, self.weights).item() + self.bias)
		prob = 1.0 / (1.0 + np.exp(-score))
		decision = 1 if prob >= 0.5 else 0
		return {
			'decision': decision,
			'confidence': float(prob)
		}