import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier

class DecisionMaker:
    def __init__(self):
        self.model = RandomForestClassifier()
        self.scaler = StandardScaler()
        
    def train(self, features, decisions):
        """
        Train the decision-making model
        features: array of input features
        decisions: array of historical decisions
        """
        scaled_features = self.scaler.fit_transform(features)
        self.model.fit(scaled_features, decisions)
    
    def make_decision(self, input_features):
        """
        Make a decision based on input features
        input_features: array of features for the current situation
        """
        scaled_input = self.scaler.transform(input_features.reshape(1, -1))
        decision = self.model.predict(scaled_input)
        confidence = self.model.predict_proba(scaled_input).max()
        
        return {
            'decision': decision[0],
            'confidence': confidence
        }