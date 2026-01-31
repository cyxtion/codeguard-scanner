import os
import requests
import json
from flask import Flask, request, jsonify

app = Flask(__name__)

def recursive_search(data, found_deps):
    """
    Recursively hunts for package-like key/values in ANY JSON structure.
    """
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(k, str) and isinstance(v, str):
                if len(v) < 20 and len(k) < 100 and " " not in k:
                    found_deps[k] = v

            if isinstance(v, (dict, list)):
                recursive_search(v, found_deps)
                
    elif isinstance(data, list):
        for item in data:
            recursive_search(item, found_deps)

@app.route('/scan', methods=['POST'])
def scan_package():
    debug_log = []
    found_dependencies = {}
    
    try:
        raw_text = request.get_data(as_text=True)
        debug_log.append(f"RAW_INPUT_START: {raw_text} :RAW_INPUT_END")

        data = request.get_json(force=True, silent=True)
        if not data and raw_text:
            try:
                data = json.loads(raw_text)
            except:
                data = {}

        if isinstance(data, str):
            try:
                data = json.loads(data)
            except:
                pass

        recursive_search(data, found_dependencies)
        cleaned_deps = {}
        for k, v in found_dependencies.items():
            if k.lower() not in ["input", "model", "parameters", "user", "prompt"]:
                cleaned_deps[k] = v
        
        found_dependencies = cleaned_deps
        debug_log.append(f"Extracted Dependencies: {json.dumps(found_dependencies)}")

    except Exception as e:
        return jsonify({"error": str(e), "debug_trace": debug_log}), 400
    report = []
    if not found_dependencies:
        return jsonify({
            "audit_results": [],
            "status": "No dependencies found",
            "debug_trace": debug_log
        })

    for package, version in found_dependencies.items():
        try:
            clean_version = str(version).replace('^', '').replace('~', '')
            
            if ":" in package:
                ecosystem = "Maven"
            else:
                ecosystem = "npm"

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
            debug_log.append(f"Scan Error ({package}): {str(e)}")

    return jsonify({
        "audit_results": report,
        "debug_trace": debug_log
    })

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080)
