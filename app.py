import os
import requests
import json
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/scan', methods=['POST'])
def scan_package():
    debug_log = []
    data = {}
    
    try:
        raw_data = request.get_data(as_text=True)
        debug_log.append(f"Received: {raw_data[:200]}")
        
        data = request.get_json(force=True, silent=True)
        if not data and raw_data:
            try:
                data = json.loads(raw_data)
            except:
                data = {}
        
        if isinstance(data, str):
             try:
                 data = json.loads(data)
             except:
                 pass
                 
    except Exception as e:
        return jsonify({"error": str(e), "debug_log": debug_log}), 400

    dependencies = data.get('dependencies', data)
    
    if isinstance(dependencies, list):
        new_deps = {}
        for item in dependencies:
            if isinstance(item, dict):
                k = item.get('name') or item.get('package')
                v = item.get('version')
                if k and v: 
                    new_deps[k] = v
        dependencies = new_deps

    if not isinstance(dependencies, dict):
        dependencies = {}

    report = []
    
    for package, version in dependencies.items():
        try:
            clean_version = str(version).replace('^', '').replace('~', '')
            
            if ":" in package:
                ecosystem = "Maven"
            else:
                ecosystem = "npm"

            debug_log.append(f"Checking {package} in {ecosystem}")

            url = "https://api.osv.dev/v1/query"
            payload = {
                "package": {"name": package, "ecosystem": ecosystem},
                "version": clean_version
            }
            
            response = requests.post(url, json=payload)
            if response.status_code == 200:
                res_json = response.json()
                if 'vulns' in res_json:
                    for vuln in res_json['vulns']:
                        report.append({
                            "package": package,
                            "version": clean_version,
                            "severity": "CRITICAL" if "critical" in str(vuln).lower() else "HIGH",
                            "id": vuln['id'],
                            "summary": vuln.get('summary', 'Vulnerability Detected')
                        })
        except Exception as e:
            debug_log.append(f"Error: {str(e)}")

    return jsonify({
        "audit_results": report,
        "debug_info": debug_log 
    })

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080)
