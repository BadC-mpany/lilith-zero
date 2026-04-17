import json
import os
from flask import Flask, render_template, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# The collector writes to this file in the parent directory (or same directory if run from there)
TELEMETRY_JSON = os.path.abspath(os.path.join(os.path.dirname(__file__), "../telemetry.json"))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/traces')
def get_traces():
    if not os.path.exists(TELEMETRY_JSON):
        return jsonify([])
    
    traces = []
    try:
        with open(TELEMETRY_JSON, 'r') as f:
            for line in f:
                if line.strip():
                    traces.append(json.loads(line))
    except Exception as e:
        print(f"Error reading telemetry: {e}")
        
    return jsonify(traces)

@app.route('/api/clear', methods=['POST'])
def clear_traces():
    # Clear both JSON and human-readable logs
    log_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../telemetry.log"))
    
    for path in [TELEMETRY_JSON, log_path]:
        try:
            if os.path.exists(path):
                with open(path, 'w') as f:
                    f.truncate(0)
        except Exception as e:
            print(f"Error clearing {path}: {e}")
            
    return jsonify({"status": "success"})

if __name__ == '__main__':
    # Start on a different port than the collector/MCP
    app.run(host='127.0.0.1', port=16617, debug=True)
