import requests
import pandas as pd
import sys
import time

def make_prediction_request(max_retries=3, retry_delay=2):
    # Load test data
    try:
        test_data = pd.read_csv('data/KDDTest+.txt')
    except FileNotFoundError:
        print("Error: Test data file not found in data/KDDTest+.txt")
        return

    # Prepare data for request
    data = {
        'data': test_data.to_dict(orient='records')
    }

    # Make POST request with retries
    url = 'http://localhost:8080/predict'
    
    for attempt in range(max_retries):
        try:
            print(f"\nAttempting to connect to server (attempt {attempt + 1}/{max_retries})...")
            response = requests.post(url, json=data)
            
            # Print response
            print("\nResponse Status:", response.status_code)
            print("\nResponse Content:")
            print(response.json())

            # If successful, print paths to result files
            if response.status_code == 200:
                result = response.json()
                print("\nResults saved to:")
                print(f"Predictions: {result['results_path']}")
                print(f"Confusion Matrix: {result['confusion_matrix_path']}")
                print(f"Performance Metrics: {result['metrics_path']}")
                print(f"\nModel Accuracy: {result['accuracy']:.4f}")
                return
            
        except requests.exceptions.ConnectionError:
            if attempt < max_retries - 1:
                print(f"Connection failed. Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
            else:
                print("\nError: Could not connect to the server. Please ensure:")
                print("1. The server (test_model.py) is running")
                print("2. The server is running on port 8080")
                print("3. No firewall is blocking the connection")
                return

if __name__ == "__main__":
    make_prediction_request()