from decision_maker import DecisionMaker
import numpy as np

def main():
    # Example usage
    decision_maker = DecisionMaker()
    
    # Sample training data (replace with your actual data)
    # Features could be: [cost, benefit, risk, time_investment]
    training_features = np.array([
        [1000, 5000, 2, 30],
        [2000, 3000, 4, 60],
        [500, 1000, 1, 10],
        # Add more training examples
    ])
    
    # Historical decisions (0: reject, 1: accept)
    historical_decisions = np.array([1, 0, 1])
    
    # Train the model
    decision_maker.train(training_features, historical_decisions)
    
    # Make a new decision
    new_situation = np.array([1500, 4000, 3, 45])
    result = decision_maker.make_decision(new_situation)
    
    print(f"Decision: {'Accept' if result['decision'] == 1 else 'Reject'}")
    print(f"Confidence: {result['confidence']:.2f}")

if __name__ == "__main__":
    main()