import os
import pandas as pd
import numpy as np
import joblib
from sklearn.preprocessing import LabelEncoder
from sklearn.impute import SimpleImputer
import sys
import warnings

# Add project root to Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

# Import DLHA after adding project root to path
from api.app import DLHA

# Create model directory if it doesn't exist
model_dir = os.path.join(current_dir, 'model')
os.makedirs(model_dir, exist_ok=True)

# Load and preprocess your data
data_path = os.path.join(current_dir, 'data', 'KDDTrain+.txt')
print(f"Loading data from: {data_path}")

# Define column names for KDD Cup dataset
columns = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'class'
]

# Read the data with column names
data = pd.read_csv(data_path, names=columns)
print("Data loaded successfully")
print(f"Dataset shape: {data.shape}")

# Prepare features and target
X = data.drop('class', axis=1)
y = data['class']

print(f"Features shape: {X.shape}")
print(f"Target shape: {y.shape}")
print("\nSample of target values:", y.value_counts().head())

# Initialize and fit label encoders
label_encoders = {}
categorical_features = ['protocol_type', 'service', 'flag']

# First encode categorical features
for feature in categorical_features:
    print(f"\nEncoding {feature}...")
    le = LabelEncoder()
    X[feature] = le.fit_transform(X[feature])
    label_encoders[feature] = le
    print(f"Unique values in {feature}: {len(le.classes_)}")
    print(f"Classes: {le.classes_}")

# Now handle numeric columns
numeric_columns = [col for col in X.columns if col not in categorical_features]
print("\nProcessing numeric columns...")

# Convert numeric columns to float and handle missing values
for col in numeric_columns:
    # Convert to numeric, replacing errors with NaN
    X[col] = pd.to_numeric(X[col], errors='coerce')
    
    # Replace NaN with column mean, if all values are NaN, replace with 0
    if X[col].isna().all():
        X[col] = 0
    else:
        X[col] = X[col].fillna(X[col].mean())

# Verify no NaN values remain
print("\nChecking for NaN values...")
nan_check = X.isna().sum()
print("Columns with NaN values:")
print(nan_check[nan_check > 0])

# Initialize and train DLHA model
print("\nTraining DLHA model...")
model = DLHA()
model.fit(X, y)
print("Model training completed")

# Save model and encoders
model_path = os.path.join(model_dir, 'dlha_model.pkl')
encoders_path = os.path.join(model_dir, 'label_encoders.pkl')

print("\nSaving model and encoders...")
joblib.dump(model, model_path)
joblib.dump(label_encoders, encoders_path)

print(f"Model saved to: {model_path}")
print(f"Encoders saved to: {encoders_path}")

# Validate saved files
print("\nValidating saved files...")
if os.path.exists(model_path) and os.path.exists(encoders_path):
    model_size = os.path.getsize(model_path) / (1024 * 1024)
    encoders_size = os.path.getsize(encoders_path) / (1024 * 1024)
    print(f"Model file size: {model_size:.2f} MB")
    print(f"Encoders file size: {encoders_size:.2f} MB")
    
    try:
        test_model = joblib.load(model_path)
        test_encoders = joblib.load(encoders_path)
        print("Files loaded successfully for validation!")
        print("Model and encoders saved and validated successfully!")
    except Exception as e:
        print(f"Error validating saved files: {str(e)}")
else:
    print("Error: Files not saved properly!")

print("\nTraining process completed!")