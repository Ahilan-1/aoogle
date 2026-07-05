import os
import json
import pickle
import warnings
import numpy as np

# Suppress XGBoost pickle loading version warnings
warnings.filterwarnings('ignore', category=UserWarning, module='xgboost')

MODEL_PATH = os.path.join(os.path.dirname(__file__), 'model.pkl')
FEATURES_PATH = os.path.join(os.path.dirname(__file__), 'feature_names.pkl')

_ranker = None

class MLRanker:
    def __init__(self):
        self.model = None
        self.feature_names = None
        self.available = False

    def load(self):
        try:
            if os.path.exists(MODEL_PATH):
                with open(MODEL_PATH, 'rb') as f:
                    self.model = pickle.load(f)
                with open(FEATURES_PATH, 'rb') as f:
                    self.feature_names = pickle.load(f)
                self.available = True
                return True
        except Exception as e:
            print(f"ML model load error: {e}")
        self.available = False
        return False

    def predict(self, query, documents):
        if not self.available or not self.model:
            return [0.0] * len(documents)
        try:
            from .features import extract_features
            X = extract_features(query, documents, self.feature_names)
            if X is None or len(X) == 0:
                return [0.0] * len(documents)
            scores = self.model.predict(X)
            return scores.tolist() if hasattr(scores, 'tolist') else list(scores)
        except Exception as e:
            print(f"ML predict error: {e}")
            return [0.0] * len(documents)


def get_ranker():
    global _ranker
    if _ranker is None:
        _ranker = MLRanker()
        _ranker.load()
    return _ranker


def train_msmarco(output_dir=None):
    from .train import run_training
    return run_training(output_dir)


def is_available():
    try:
        import xgboost
        return True
    except ImportError:
        return False
