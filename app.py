import os
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/scan', methods=['POST'])
def scan_package():
    data = request.json
    dependencies = data.get('dependencies', {})

    report = []

    for package, version in dependencies.items():
        clean_version = version.replace('^', '').replace('~', '')

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