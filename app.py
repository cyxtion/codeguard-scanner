import os
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/scan', methods=['POST'])
def scan_package():
    try:
        data = request.get_json(force=True, silent=True)
        if not data:
            import json
            data = json.loads(request.data)
            
        print(f"Received Data: {data}")

        dependencies = data.get('dependencies', data)

        if isinstance(dependencies, str):
            import json
            dependencies = json.loads(dependencies)

    except Exception as e:
        return jsonify({"error": f"Failed to parse input: {str(e)}"}), 400

    report = []
    
    # Check each package against Google OSV
    # We use .items() if it's a dict, otherwise skip
    if isinstance(dependencies, dict):
        for package, version in dependencies.items():
            clean_version = str(version).replace('^', '').replace('~', '')
            
            url = "https://api.osv.dev/v1/query"
            payload = {
                "package": {"name": package, "ecosystem": "npm"},
                "version": clean_version
            }
            
            try:
                response = requests.post(url, json=payload)
                res_json = response.json()
                
                if 'vulns' in res_json:
                    for vuln in res_json['vulns']:
                        report.append({
                            "package": package,
                            "version": clean_version,
                            "severity": "HIGH", 
                            "id": vuln['id'],
                            "summary": vuln.get('summary', 'Security Vulnerability Detected')
                        })
            except Exception as e:
                print(f"Error checking {package}: {e}")

    return jsonify({"audit_results": report})

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080)
