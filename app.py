import os
import requests
import json
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/scan', methods=['POST'])
def scan_package():
    data = {}
    try:
        data = request.get_json(force=True, silent=True)

        if data is None:
            if request.data:
                try:
                    data = json.loads(request.data)
                except:
                    data = {}
            else:
                data = {}

        if isinstance(data, str):
             try:
                 data = json.loads(data)
             except:
                 pass
                 
    except Exception as e:
        print(f"Input parsing failed: {e}")
        data = {}

    dependencies = data.get('dependencies', data)

    if not isinstance(dependencies, dict):
        dependencies = {}

    report = []

    for package, version in dependencies.items():
        try:
            clean_version = str(version).replace('^', '').replace('~', '')

            url = "https://api.osv.dev/v1/query"
            payload = {
                "package": {"name": package, "ecosystem": "npm"},
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
                            "severity": "HIGH", 
                            "id": vuln['id'],
                            "summary": vuln.get('summary', 'Security Vulnerability Detected')
                        })
        except Exception as e:
            print(f"Error checking {package}: {e}")

    return jsonify({"audit_results": report})

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080)
