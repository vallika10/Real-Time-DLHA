import pandas as pd
import numpy as np
from sklearn.naive_bayes import GaussianNB
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import os

class DLHA:
    def __init__(self):
        self.layer1_classifier = GaussianNB()  # Naive Bayes for DoS and Probe
        self.layer2_classifier = SVC(kernel='rbf', probability=True)  # SVM for rear attacks
        self.pca = PCA(n_components=0.95)  # Preserve 95% variance
        self.scaler = StandardScaler()
    
    def preprocess_data(self, X):
        if not hasattr(self.scaler, 'mean_'):
            X_scaled = self.scaler.fit_transform(X)
            X_pca = self.pca.fit_transform(X_scaled)
        else:
            X_scaled = self.scaler.transform(X)
            X_pca = self.pca.transform(X_scaled)
        return X_pca
    
    def train(self, X, y):
        X_processed = self.preprocess_data(X)
        
        # Layer 1: Train Naive Bayes for DoS and Probe
        dos_probe_mask = y.isin(['DoS', 'Probe'])
        if dos_probe_mask.any():
            self.layer1_classifier.fit(X_processed[dos_probe_mask], y[dos_probe_mask])
        
        # Layer 2: Train SVM for rear attacks
        rear_normal_mask = y.isin(['R2L', 'U2R', 'Normal'])
        if rear_normal_mask.any():
            self.layer2_classifier.fit(X_processed[rear_normal_mask], y[rear_normal_mask])
        
        # Save the trained model
        if not os.path.exists('model'):
            os.makedirs('model')
        joblib.dump(self, 'model/dlha_model.pkl')
    
    def predict(self, X):
        X_processed = self.preprocess_data(X)
        
        try:
            # Layer 1 predictions
            layer1_pred = self.layer1_classifier.predict_proba(X_processed)
            
            # Layer 2 predictions
            layer2_pred = self.layer2_classifier.predict_proba(X_processed)
            
            # Combine predictions based on confidence
            final_predictions = []
            for l1_prob, l2_prob in zip(layer1_pred, layer2_pred):
                if max(l1_prob) > 0.8:  # High confidence in Layer 1
                    final_predictions.append('DoS' if l1_prob[0] > l1_prob[1] else 'Probe')
                else:
                    final_predictions.append(self.layer2_classifier.classes_[np.argmax(l2_prob)])
            
            return np.array(final_predictions)
        except Exception as e:
            print(f"Prediction error: {str(e)}")
            return np.array(['Unknown'] * len(X))

    def predict_proba(self, X):
        X_processed = self.preprocess_data(X)
        
        try:
            # Get probabilities from both layers
            layer1_probs = self.layer1_classifier.predict_proba(X_processed)
            layer2_probs = self.layer2_classifier.predict_proba(X_processed)
            
            # Return the maximum probability as confidence
            return np.maximum(layer1_probs.max(axis=1), layer2_probs.max(axis=1))
        except Exception as e:
            print(f"Probability prediction error: {str(e)}")
            return np.array([0.0] * len(X))

def load_and_prepare_data():
    try:
        # Load preprocessed data
        train_data = pd.read_csv('data/processed_train.csv')
        test_data = pd.read_csv('data/processed_test.csv')
        
        # Separate features and labels
        X_train = train_data.drop('label', axis=1)
        y_train = train_data['label']
        X_test = test_data.drop('label', axis=1)
        y_test = test_data['label']
        
        return X_train, X_test, y_train, y_test
    except Exception as e:
        print(f"Error loading data: {str(e)}")
        return None, None, None, None

def evaluate_model():
    # Load data
    X_train, X_test, y_train, y_test = load_and_prepare_data()
    if X_train is None:
        return
    
    # Initialize and train model
    print("Training DLHA model...")
    model = DLHA()
    model.train(X_train, y_train)
    
    # Make predictions
    print("Making predictions...")
    predictions = model.predict(X_test)
    
    # Calculate confidence scores
    confidence_scores = model.predict_proba(X_test)
    
    # Print results
    print("\nClassification Report:")
    print(classification_report(y_test, predictions))
    
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, predictions))
    
    print("\nAverage Confidence Score:", np.mean(confidence_scores))

if __name__ == "__main__":
    evaluate_model()