import re
from collections import defaultdict
from datetime import datetime

LOG_FILE = 'test_access.log'

ip_counts = defaultdict(int)
ip_timestamps = defaultdict(list)

def check_content_anomaly(request_path):
    attack_signatures = [
        "union select",
        "../",
        "/etc/passwd",
        "phpmyadmin",
        "wp-admin",
        "select * from",
        ".env",
        "config.php"
    ]
    
    for signature in attack_signatures:
        if signature in request_path.lower():
            return True
    return False

def parse_log_line(line):
    pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(.*?)\] "(.*?)" (\d{3})'
    match = re.match(pattern, line)
    
    if match:
        ip = match.group(1)
        timestamp_str = match.group(2)
        request = match.group(3)
        status_code = match.group(4)
        
        timestamp = datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S %z')
        
        return {
            'ip': ip,
            'timestamp': timestamp,
            'request': request,
            'status_code': status_code
        }
    return None

def analyze_logs(log_file):
    anomalies = []
    
    try:
        with open(log_file, 'r') as f:
            for line in f:
                parsed = parse_log_line(line.strip())
                
                if parsed:
                    ip = parsed['ip']
                    timestamp = parsed['timestamp']
                    request = parsed['request']
                    
                    ip_counts[ip] += 1
                    ip_timestamps[ip].append(timestamp)
                    
                    if check_content_anomaly(request):
                        anomalies.append({
                            'type': 'Suspicious Content',
                            'ip': ip,
                            'request': request,
                            'timestamp': timestamp
                        })
        
        for ip, timestamps in ip_timestamps.items():
            if len(timestamps) > 50:
                timestamps_sorted = sorted(timestamps)
                time_diff = (timestamps_sorted[-1] - timestamps_sorted[0]).total_seconds()
                
                if time_diff < 300:
                    anomalies.append({
                        'type': 'Brute Force Attack',
                        'ip': ip,
                        'request_count': len(timestamps),
                        'time_window': f'{time_diff:.0f} seconds'
                    })
        
        return anomalies
    
    except FileNotFoundError:
        print(f"Error: File '{log_file}' not found.")
        return []

def display_results(anomalies):
    if not anomalies:
        print("No anomalies detected.")
        return
    
    print(f"\n{'='*60}")
    print(f"SECURITY ANOMALIES DETECTED: {len(anomalies)}")
    print(f"{'='*60}\n")
    
    for i, anomaly in enumerate(anomalies, 1):
        print(f"[{i}] {anomaly['type']}")
        print(f"    IP: {anomaly['ip']}")
        
        if 'request' in anomaly:
            print(f"    Request: {anomaly['request']}")
            print(f"    Time: {anomaly['timestamp']}")
        
        if 'request_count' in anomaly:
            print(f"    Requests: {anomaly['request_count']}")
            print(f"    Time Window: {anomaly['time_window']}")
        
        print()

if __name__ == "__main__":
    print(f"Analyzing log file: {LOG_FILE}")
    print("="*60)
    
    anomalies = analyze_logs(LOG_FILE)
    display_results(anomalies)
    
    print(f"\nTotal IPs analyzed: {len(ip_counts)}")
    print(f"Total requests processed: {sum(ip_counts.values())}")
