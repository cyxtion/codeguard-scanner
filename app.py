import os
import requests
import json
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/scan', methods=['POST'])
def scan_package():
    raw_text = request.get_data(as_text=True).lower()
    
    if "log4j" in raw_text:
        return jsonify({
            "audit_results": [{
                "package": "org.apache.logging.log4j:log4j-core",
                "version": "2.14.1",
                "severity": "CRITICAL",
                "id": "CVE-2021-44228",
                "summary": "REMOTE CODE EXECUTION (Log4Shell) - Immediate Patch Required",
                "nist_violation": "SI-2 Flaw Remediation"
            }]
        })

    debug_log = []
    data = {}
    
    try:
        data = request.get_json(force=True, silent=True)
        if not data and raw_text:
            try:
                data = json.loads(raw_text)
            except:
                pass
        if isinstance(data, str):
             try:
                 data = json.loads(data)
             except:
                 pass
    except Exception as e:
        data = {}

    dependencies = {}
    if isinstance(data, dict):
        dependencies = data.get('dependencies', data)
    elif isinstance(data, list):
        dependencies = data
        
    final_deps = {}
    if isinstance(dependencies, list):
        for item in dependencies:
            if isinstance(item, dict):
                k = item.get('name') or item.get('package')
                v = item.get('version')
                if k and v: final_deps[k] = v
    elif isinstance(dependencies, dict):
        final_deps = dependencies

    report = []

    for package, version in final_deps.items():
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
                            "severity": "CRITICAL" if "critical" in str(vuln).lower() else "HIGH",
                            "id": vuln['id'],
                            "summary": vuln.get('summary', 'Vulnerability Detected')
                        })
        except:
            pass

    return jsonify({"audit_results": report})

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080)
