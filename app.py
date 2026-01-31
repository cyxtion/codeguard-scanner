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
        data = request.get_json(force=True, silent=True)
        if not data:
            raw_data = request.get_data(as_text=True)
            if raw_data:
                try:
                    data = json.loads(raw_data)
                except:
                    pass

        if isinstance(data, str):
             try:
                 data = json.loads(data)
             except:
                 pass
                 
    except Exception as e:
        debug_log.append(f"Parse Error: {str(e)}")
        data = {}

    dependencies = {}
    
    if isinstance(data, dict):
        dependencies = data.get('dependencies', data)
    elif isinstance(data, list):
        dependencies = data
    else:
        dependencies = {}

    final_deps = {}
    
    if isinstance(dependencies, list):
        for item in dependencies:
            if isinstance(item, dict):
                k = item.get('name') or item.get('package') or item.get('dependency') or item.get('key')
                v = item.get('version') or item.get('ver') or item.get('value')
                if k and v: 
                    final_deps[k] = v
                    
    elif isinstance(dependencies, dict):
        final_deps = dependencies

    report = []
    
    for package, version in final_deps.items():
        try:
            clean_version = str(version).replace('^', '').replace('~', '')

            if ":" in package:
                ecosystem = "Maven"
            else:
                ecosystem = "npm"

            debug_log.append(f"Checking {package} ({clean_version}) in {ecosystem}")

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
            debug_log.append(f"Scan Error: {str(e)}")

    return jsonify({
        "audit_results": report,
        "debug_info": debug_log 
    })

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080)
