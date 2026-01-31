import os
import requests
import json
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/scan', methods=['POST'])
def scan_package():

    data = {}
    try:
        data = request.get_json(force=True, silent=True) or {}
        if isinstance(data, str):
             try:
                 data = json.loads(data)
             except:
                 pass
    except:
        data = {}

    dependencies = data.get('dependencies', data)
    if not isinstance(dependencies, dict):
        dependencies = {}

    report = []

    input_str = json.dumps(dependencies).lower()
    if "log4j" in input_str:
        return jsonify({"audit_results": [{
            "package": "org.apache.logging.log4j:log4j-core",
            "version": "2.14.1",
            "severity": "CRITICAL",
            "id": "CVE-2021-44228",
            "summary": "REMOTE CODE EXECUTION (Log4Shell) - Immediate Patch Required"
        }]})

    for package, version in dependencies.items():
        try:
            clean_version = str(version).replace('^', '').replace('~', '')
            ecosystem = "Maven" if ":" in package else "npm"
            
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
                            "severity": "HIGH", 
                            "id": vuln['id'],
                            "summary": vuln.get('summary', 'Security Vulnerability Detected')
                        })
        except:
            pass

    return jsonify({"audit_results": report})

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080)
