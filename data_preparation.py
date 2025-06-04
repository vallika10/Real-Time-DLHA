import pandas as pd
import numpy as np
import requests
import os
import joblib
from sklearn.preprocessing import LabelEncoder

def download_dataset():
    # Download NSL-KDD training and testing datasets
    train_url = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain%2B.txt"
    test_url = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest%2B.txt"
    
    train_file = "data/KDDTrain+.txt"
    test_file = "data/KDDTest+.txt"
    
    if not os.path.exists('data'):
        os.makedirs('data')
    
    print("Downloading training dataset...")
    response = requests.get(train_url)
    with open(train_file, 'wb') as f:
        f.write(response.content)
    
    print("Downloading testing dataset...")
    response = requests.get(test_url)
    with open(test_file, 'wb') as f:
        f.write(response.content)

def prepare_dataset():
    # Column names for the dataset
    columns = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 
              'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
              'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
              'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
              'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
              'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
              'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
              'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
              'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
              'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label', 'difficulty']
    
    print("Loading datasets...")
    train_data = pd.read_csv('data/KDDTrain+.txt', names=columns)
    test_data = pd.read_csv('data/KDDTest+.txt', names=columns)
    
    print("Processing datasets...")
    # Drop difficulty column
    train_data = train_data.drop('difficulty', axis=1)
    test_data = test_data.drop('difficulty', axis=1)
    
    # Map attack types to main categories
    attack_mapping = {
        'normal': 'Normal',
        'neptune': 'DoS', 'back': 'DoS', 'land': 'DoS', 'pod': 'DoS', 'smurf': 'DoS', 'teardrop': 'DoS',
        'satan': 'Probe', 'ipsweep': 'Probe', 'nmap': 'Probe', 'portsweep': 'Probe',
        'guess_passwd': 'R2L', 'ftp_write': 'R2L', 'imap': 'R2L', 'phf': 'R2L', 'multihop': 'R2L', 
        'warezmaster': 'R2L', 'warezclient': 'R2L', 'spy': 'R2L',
        'buffer_overflow': 'U2R', 'loadmodule': 'U2R', 'perl': 'U2R', 'rootkit': 'U2R'
    }
    
    train_data['label'] = train_data['label'].map(lambda x: attack_mapping.get(x.lower(), 'Normal'))
    test_data['label'] = test_data['label'].map(lambda x: attack_mapping.get(x.lower(), 'Normal'))
    
    # Convert categorical features
    categorical_columns = ['protocol_type', 'service', 'flag']
    label_encoders = {}
    
    for column in categorical_columns:
        label_encoders[column] = LabelEncoder()
        train_data[column] = label_encoders[column].fit_transform(train_data[column])
        test_data[column] = label_encoders[column].transform(test_data[column])
    
    # Save label encoders for future use
    if not os.path.exists('model'):
        os.makedirs('model')
    joblib.dump(label_encoders, 'model/label_encoders.pkl')
    
    print("Saving processed datasets...")
    train_data.to_csv('data/processed_train.csv', index=False)
    test_data.to_csv('data/processed_test.csv', index=False)
    
    return train_data, test_data

if __name__ == "__main__":
    print("Starting data preparation...")
    download_dataset()
    train_data, test_data = prepare_dataset()
    print("Data preparation completed!")
    print(f"Training set shape: {train_data.shape}")
    print(f"Testing set shape: {test_data.shape}")