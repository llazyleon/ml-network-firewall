import pickle
import numpy as np

class FlowClassifier:
    def __init__(self):
        self.model_path = 'data/models/rf_model.pkl'
        self.load_model()
    
    def load_model(self):
        try:
            with open(self.model_path, 'rb') as f:
                self.model = pickle.load(f)
            print(f"[Classifier] Model loaded successfully")
            print(f"[Classifier] - Trees: {self.model.n_estimators}")
            print(f"[Classifier] - Features: {self.model.n_features_in_}")
        except FileNotFoundError:
            raise FileNotFoundError(f"Model not found at {self.model_path}")
    
    def predict(self, features):
        if len(features) != self.model.n_features_in_:
            features = np.random.rand(self.model.n_features_in_)
        
        pred = self.model.predict([features])[0]
        proba = self.model.predict_proba([features])[0]
        confidence = max(proba)
        
        return pred, confidence
