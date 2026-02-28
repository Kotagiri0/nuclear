def generate_report(findings, output_format='text'):
    if output_format == 'text':
        return generate_text_report(findings)
    elif output_format == 'json':
        return generate_json_report(findings)
    elif output_format == 'sarif':
        return generate_sarif_report(findings)
    else:
        raise ValueError(f"Unsupported output format: {output_format}")

def generate_text_report(findings):
    report_lines = []
    for finding in findings:
        report_lines.append(f"{finding['severity']}: {finding['message']}")
    return "\n".join(report_lines)

def generate_json_report(findings):
    import json
    return json.dumps(findings, indent=4)

def generate_sarif_report(findings):
    sarif_report = {
        "$schema": "http://json.schemastore.org/sarif-2.1.0",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Nuclear Scanner",
                    "version": "0.1",
                    "informationUri": "https://example.com",
                    "rules": []
                }
            },
            "results": []
        }]
    }
    
    for finding in findings:
        sarif_report["runs"][0]["results"].append({
            "ruleId": finding['id'],
            "level": finding['severity'].lower(),
            "message": {
                "text": finding['message']
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": finding['file']
                    },
                    "region": {
                        "startLine": finding['line']
                    }
                }
            }]
        })
    
    return json.dumps(sarif_report, indent=4)