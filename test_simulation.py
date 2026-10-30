import urllib.request
import json

def test_pipeline():
    base_url = 'http://127.0.0.1:5000'
    
    # 1. Reset simulation
    req_reset = urllib.request.Request(f'{base_url}/api/simulation/reset', method='POST')
    urllib.request.urlopen(req_reset)

    scenarios = ['exfiltration', 'rogue_admin', 'impossible_travel', 'snooping']
    for sc in scenarios:
        req = urllib.request.Request(
            f'{base_url}/api/simulation/trigger-scenario',
            data=json.dumps({'scenario': sc}).encode('utf-8'),
            headers={'Content-Type': 'application/json'},
            method='POST'
        )
        res = json.loads(urllib.request.urlopen(req).read())
        print(f"Triggered '{sc}': {res['incidents_triggered']} incidents, {res['events_injected']} logs injected")

    # 2. Check analytics
    status = json.loads(urllib.request.urlopen(f'{base_url}/api/status').read())
    print("\nAnalytics Summary:")
    print("  Threat Level:", status['analytics']['threat_level'])
    print("  Total Ingested Logs:", status['analytics']['total_logs'])
    print("  Total Flagged Incidents:", status['analytics']['total_incidents'])
    print("  High-Risk Users:", status['analytics']['high_risk_users_count'])

    # 3. Check Incidents
    inc_data = json.loads(urllib.request.urlopen(f'{base_url}/api/incidents').read())
    print(f"\nIncidents ({len(inc_data['incidents'])}):")
    for inc in inc_data['incidents']:
        print(f"  [{inc['rule_id']}] {inc['severity']} | {inc['user_name']} ({inc['user_id']})")
        print(f"       -> Title: {inc['title']}")
        print(f"       -> Score: {inc['risk_score']}/100 | MITRE: {inc['mitre_technique']}")
        print(f"       -> Linked Events ({len(inc['correlated_events'])}): {[e['action'] for e in inc['correlated_events']]}")

    # 4. Check user risk leaderboard
    user_data = json.loads(urllib.request.urlopen(f'{base_url}/api/users').read())
    print("\nUser Risk Leaderboard:")
    for u in user_data['users']:
        print(f"  * {u['user_name']:18} | Risk Score: {u['risk_score']:3}/100 | Status: {u['status']:16} | Incidents: {u['incident_count']}")

    # 5. Check report export
    report = urllib.request.urlopen(f'{base_url}/api/export-report').read().decode('utf-8')
    print(f"\nGenerated Forensic Incident Report: {len(report.splitlines())} lines.")

if __name__ == '__main__':
    test_pipeline()
