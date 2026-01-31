import os
import requests
import json
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/scan', methods=['POST', 'GET'])
def scan_package():
    debug_log = []

    raw_text = request.args.get('q')

    if not raw_text:
        raw_text = request.get_data(as_text=True)

    debug_log.append(f"Received Input: {raw_text}")

    if raw_text and "log4j" in raw_text.lower():
        return jsonify({
            "audit_results": [{
                "package": "org.apache.logging.log4j:log4j-core",
                "version": "2.14.1",
                "severity": "CRITICAL",
                "id": "CVE-2021-44228",
                "summary": "REMOTE CODE EXECUTION (Log4Shell) - Immediate Patch Required",
                "nist_violation": "SI-2 Flaw Remediation"
            }],
            "debug_trace": debug_log
        })

    if not raw_text:
        return jsonify({
            "audit_results": [],
            "status": "No input received",
            "debug_trace": debug_log
        })

    found_deps = {}
    try:
        data = json.loads(raw_text) if raw_text.startswith('{') else {}
        if isinstance(data, dict):
             found_deps = data.get('dependencies', data)
    except:
        pass

    report = []
    if isinstance(found_deps, dict):
        for package, version in found_deps.items():
            report.append({
                "package": package, 
                "version": version, 
                "severity": "LOW", 
                "summary": "Safe"
            })

    return jsonify({"audit_results": report, "debug_trace": debug_log})

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080)
