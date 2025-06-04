import os
import pandas as pd
import numpy as np
import joblib
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
from sklearn.preprocessing import LabelEncoder
import warnings
import seaborn as sns
import matplotlib.pyplot as plt
from flask import Flask, request, jsonify, send_file, render_template_string
from flask_cors import CORS
import datetime

# Filter warnings
warnings.filterwarnings('ignore')

app = Flask(__name__)
CORS(app)

# Load model and encoders
model_dir = os.path.join(os.path.dirname(__file__), 'model')
model = joblib.load(os.path.join(model_dir, 'dlha_model.pkl'))
encoders = joblib.load(os.path.join(model_dir, 'label_encoders.pkl'))

# Define columns
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
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
]

@app.route('/')
def home():
    html = '''
    <html>
        <head>
            <title>Network Intrusion Detection</title>
            <style>
                body { font-family: Arial; margin: 40px; background-color: #f5f5f5; }
                .container { max-width: 1200px; margin: auto; background-color: white; padding: 20px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
                h1 { color: #2c3e50; text-align: center; }
                .form-container { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; }
                .form-group { margin-bottom: 15px; }
                label { display: block; margin-bottom: 5px; color: #34495e; }
                input, select { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
                .submit-btn { grid-column: span 3; background-color: #3498db; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; }
                .submit-btn:hover { background-color: #2980b9; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Network Intrusion Detection System</h1>
                <form action="/predict" method="post">
                    <div class="form-container">
                        <div class="form-group">
                            <label>Duration:</label>
                            <input type="number" name="duration" required>
                        </div>
                        <div class="form-group">
                            <label>Protocol Type:</label>
                            <select name="protocol_type" required>
                                <option value="tcp">TCP</option>
                                <option value="udp">UDP</option>
                                <option value="icmp">ICMP</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label>Service:</label>
                            <select name="service" required>
                                <option value="http">HTTP</option>
                                <option value="ftp">FTP</option>
                                <option value="smtp">SMTP</option>
                                <option value="ssh">SSH</option>
                                <option value="telnet">Telnet</option>
                                <option value="dns">DNS</option>
                                <option value="other">Other</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label>Flag:</label>
                            <select name="flag" required>
                                <option value="SF">SF (Normal)</option>
                                <option value="REJ">REJ (Rejected)</option>
                                <option value="RSTO">RSTO (Reset Out)</option>
                                <option value="RSTR">RSTR (Reset Root)</option>
                                <option value="S0">S0 (No Response)</option>
                                <option value="S1">S1 (Connection Established)</option>
                                <option value="S2">S2 (Client Established)</option>
                                <option value="S3">S3 (Server Established)</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label>Source Bytes:</label>
                            <input type="number" name="src_bytes" required>
                        </div>
                        <div class="form-group">
                            <label>Destination Bytes:</label>
                            <input type="number" name="dst_bytes" required>
                        </div>
                        <div class="form-group">
                            <label>Count:</label>
                            <input type="number" name="count" value="0" required>
                        </div>
                        <div class="form-group">
                            <label>Service Count:</label>
                            <input type="number" name="srv_count" value="0" required>
                        </div>
                        <div class="form-group">
                            <label>Error Rate:</label>
                            <input type="number" name="serror_rate" value="0" step="0.01" min="0" max="1" required>
                        </div>
                        <div class="form-group">
                            <label>Service Error Rate:</label>
                            <input type="number" name="srv_serror_rate" value="0" step="0.01" min="0" max="1" required>
                        </div>
                        <div class="form-group">
                            <label>Same Service Rate:</label>
                            <input type="number" name="same_srv_rate" value="0" step="0.01" min="0" max="1" required>
                        </div>
                        <div class="form-group">
                            <label>Different Service Rate:</label>
                            <input type="number" name="diff_srv_rate" value="0" step="0.01" min="0" max="1" required>
                        </div>
                        <button type="submit" class="submit-btn">Detect Intrusion</button>
                    </div>
                </form>
            </div>
        </body>
    </html>
    '''
    return html

@app.route('/health')
def health_check():
    try:
        start_time = datetime.datetime.now()
        model_status = model is not None
        encoders_status = encoders is not None
        results_dir = os.path.join(os.path.dirname(__file__), 'results')
        results_status = os.path.exists(results_dir) and os.access(results_dir, os.W_OK)
        response_time = (datetime.datetime.now() - start_time).total_seconds()
        status = "healthy" if all([model_status, encoders_status, results_status]) else "unhealthy"
        
        return jsonify({
            "status": status,
            "timestamp": datetime.datetime.now().isoformat(),
            "response_time": response_time,
            "checks": {
                "model_loaded": model_status,
                "encoders_loaded": encoders_status,
                "results_directory": results_status
            },
            "version": "1.0.0"
        }), 200 if status == "healthy" else 503
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e),
            "timestamp": datetime.datetime.now().isoformat()
        }), 500

@app.route('/predict', methods=['GET', 'POST'])
def predict():
    if request.method == 'GET':
        return jsonify({
            "message": "Please use POST method to make predictions",
            "status": "error",
            "code": 405
        }), 405

    try:
        if request.form:
            input_data = {col: 0 for col in columns}
            for key in request.form:
                if key in columns:
                    try:
                        input_data[key] = float(request.form[key])
                    except ValueError:
                        input_data[key] = request.form[key]

            test_data = pd.DataFrame([input_data])
            categorical_features = ['protocol_type', 'service', 'flag']
            
            for feature in categorical_features:
                known_labels = set(encoders[feature].classes_)
                if test_data[feature].iloc[0] not in known_labels:
                    test_data[feature] = encoders[feature].classes_[0]
                test_data[feature] = encoders[feature].transform(test_data[feature])

            test_data = test_data.astype(float)
            prediction = model.predict(test_data)

            return render_template_string('''
                <html>
                    <head>
                        <title>Prediction Result</title>
                        <style>
                            body { font-family: Arial; margin: 40px; background-color: #f5f5f5; }
                            .container { max-width: 800px; margin: auto; background-color: white; padding: 20px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
                            h1 { color: #2c3e50; text-align: center; }
                            .result { margin-top: 20px; padding: 20px; background-color: #f8f9fa; border-radius: 5px; text-align: center; }
                            .prediction { font-size: 24px; font-weight: bold; }
                            .normal { color: #27ae60; }
                            .attack { color: #c0392b; }
                            .back-btn { display: inline-block; margin-top: 20px; padding: 10px 20px; background-color: #3498db; color: white; text-decoration: none; border-radius: 5px; }
                        </style>
                    </head>
                    <body>
                        <div class="container">
                            <h1>Prediction Result</h1>
                            <div class="result">
                                <div class="prediction {% if prediction[0] == 'normal' %}normal{% else %}attack{% endif %}">
                                    {{ prediction[0] }}
                                </div>
                            </div>
                            <div style="text-align: center;">
                                <a href="/" class="back-btn">Back to Input Form</a>
                            </div>
                        </div>
                    </body>
                </html>
            ''', prediction=prediction)
        else:
            return jsonify({
                "message": "No form data received",
                "status": "error"
            }), 400

    except Exception as e:
        return jsonify({
            "message": "Error during prediction",
            "error": str(e),
            "status": "error"
        }), 500

if __name__ == '__main__':
    results_dir = os.path.join(os.path.dirname(__file__), 'results')
    os.makedirs(results_dir, exist_ok=True)
    app.run(host='0.0.0.0', port=8080, debug=True)