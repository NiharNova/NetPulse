import urllib.request
import json

def test():
    # 1. Attack injection
    req_att = urllib.request.Request(
        'http://127.0.0.1:8000/api/capture/simulate-attack',
        data=json.dumps({'attack_type': 'port_scan'}).encode(),
        headers={'Content-Type': 'application/json'}
    )
    res = urllib.request.urlopen(req_att)
    print('Attack response:', json.loads(res.read().decode()))

    # 2. Get Alerts
    req_alerts = urllib.request.urlopen('http://127.0.0.1:8000/api/alerts')
    alerts_data = json.loads(req_alerts.read().decode())
    print('Total alerts in SQLite:', alerts_data['total'])
    if alerts_data['alerts']:
        print('Latest alert:', alerts_data['alerts'][0]['alert_type'], '|', alerts_data['alerts'][0]['details'])

    # 3. Subnet tool
    req_sub = urllib.request.Request(
        'http://127.0.0.1:8000/api/tools/subnet',
        data=json.dumps({'network': '192.168.1.100/24'}).encode(),
        headers={'Content-Type': 'application/json'}
    )
    sub_res = urllib.request.urlopen(req_sub)
    sub_data = json.loads(sub_res.read().decode())
    print('Subnet tool test:', sub_data['network_address'], sub_data['usable_host_range'])

    # 4. Port scan
    req_scan = urllib.request.Request(
        'http://127.0.0.1:8000/api/scan',
        data=json.dumps({'target_host': '127.0.0.1', 'port_range': '8000', 'protocol': 'TCP', 'authorized': True}).encode(),
        headers={'Content-Type': 'application/json'}
    )
    scan_res = urllib.request.urlopen(req_scan)
    scan_data = json.loads(scan_res.read().decode())
    print('Port scan test port 8000:', scan_data['results'])

if __name__ == '__main__':
    test()
