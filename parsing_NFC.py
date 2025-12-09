import re
import pandas as pd
import sys
import os
from datetime import datetime
from collections import deque
from rich.console import Console
from rich.table import Table

console = Console()

columns = [
    ("timestamp", "cyan"),
    ("time_delta", "bright_cyan"),
    ("command_type", "yellow"),
    ("CLA", "green"),
    ("INS", "green"),
    ("P1", "green"),
    ("P2", "green"),
    ("Lc", "green"),
    ("payload", "magenta"),
    ("protocol_version", "white"),
    ("vehicle_ePK", "white"),
    ("transaction_identifier", "white"),
    ("vehicle_identifier", "white"),
    ("endpoint_ePK", "white"),
    ("cryptogram", "white"),
    ("curve_point_y", "white"),
    ("vehicle_evi_m1", "white"),
    ("command_mac", "red"),
    ("response_mac", "blue"),
    ("status", "white"),
]

# Command 파싱
def parse_command_apdu(data, is_auth0=False, is_auth1=False, is_spake2_verify=False):
    parsed = {}
    parsed['CLA'] = data[0:2]
    parsed['INS'] = data[2:4]
    parsed['P1'] = data[4:6]
    parsed['P2'] = data[6:8]
    parsed['Lc'] = data[8:10]

    # AUTH0, AUTH1: tag 파싱, command_mac 없음
    if is_auth0:
        # AUTH0: tag별 상세 파싱
        if len(data) > 12:
            payload = data[10:-2]
            parsed['status'] = data[-2:]
        else:
            payload = data[10:]
            parsed['status'] = ''
        parsed['command_mac'] = ''
        parsed.update(parse_auth0_payload(payload))
        
    elif is_auth1:
        # AUTH1: 전체 payload만 (tag파싱X), command_mac 없음
        if len(data) > 12:
            parsed['payload'] = data[10:-2]
            parsed['status'] = data[-2:]
        else:
            parsed['payload'] = data[10:]
            parsed['status'] = ''
    
    elif is_spake2_verify:
        if len(data) > 12:
            payload = data[10:-2]
            parsed['status'] = data[-2:]
        else:
            payload = data[10:]
            parsed['status'] = ''
        parsed['command_mac'] = '' 
        parsed.update(parse_spake2_verify_payload(payload))
        
    else:
        # 나머지 명령
        if len(data) > 48:
            payload = data[10:-36]
            parsed['payload'] = payload
            parsed['command_mac'] = data[-36:-4]
            parsed['status'] = data[-4:]
        elif len(data) > 12:
            payload = data[10:-2]
            parsed['payload'] = payload
            parsed['command_mac'] = ''
            parsed['status'] = data[-2:]
        else:
            payload = data[10:]
            parsed['payload'] = payload
            parsed['command_mac'] = ''
            parsed['status'] = ''
    return parsed


# Response 파싱
def parse_response_apdu(data, is_auth0_resp=False):
    parsed = {}
    if is_auth0_resp:
        # TLV 파싱 (86/9D)
        payload = data[:-4] if data.endswith("9000") else data
        pos = 0
        tags = {
            "86": "endpoint_ePK",
            "9d": "cryptogram"
        }
        # 미리 초기화
        for key in tags.values():
            parsed[key] = ""
        while pos + 4 <= len(payload):
            tag = payload[pos:pos+2].lower()
            length = int(payload[pos+2:pos+4], 16) * 2
            value = payload[pos+4:pos+4+length]
            tlv = payload[pos:pos+4+length]
            field = tags.get(tag)
            if field:
                parsed[field] = tlv
            pos += 4 + length
        parsed['payload'] = ''
        parsed['response_mac'] = ''
        parsed['status'] = data[-4:] if data.endswith("9000") else ""
    else:
        # 기존 로직 (response_mac 포함)
        if len(data) >= 4:
            if len(data) > 40:
                parsed['payload'] = data[:-36-4]
                parsed['response_mac'] = data[-36:-4]
                parsed['status'] = data[-4:]
            else:
                parsed['payload'] = data[:-4]
                parsed['response_mac'] = ''
                parsed['status'] = data[-4:]
        else:
            parsed['payload'] = data
            parsed['response_mac'] = ''
            parsed['status'] = ''
        # 나머지 필드는 빈 값
        parsed['endpoint_ePK'] = ''
        parsed['cryptogram'] = ''
    return parsed

# Command type 분류
def classify_and_parse_apdu(data, prev_command_type=None):
    # status only (CONTROL FLOW response)
    if data == "9000" or (len(data) == 4 and data.endswith("9000")):
        return "CONTROL FLOW response", parse_response_apdu(data)
    
    # COMMAND 
    if len(data) >=6:
        cla = data[0:2]
        ins = data[2:4]
        if data.startswith("00a40400"):
            return "SELECT", parse_command_apdu(data)
        if data.startswith("80300000"):
            return "SPAKE2+ REQUEST", parse_command_apdu(data)
        if data.startswith("80320000"):
            return "SPAKE2+ VERIFY", parse_command_apdu(data, is_spake2_verify=True)
        if cla == "80" and ins == "80":
            return "AUTH0", parse_command_apdu(data, is_auth0=True)
        if cla == "80" and ins == "81":
            return "AUTH1", parse_command_apdu(data, is_auth1=True)
        if data.startswith("84d4"):
            return "WRITE DATA", parse_command_apdu(data)
        if data.startswith("84ca"):
            return "GET DATA", parse_command_apdu(data)
        if data.startswith("84c0"):
            return "GET RESPONSE", parse_command_apdu(data)
        if data.startswith("84c9"):
            return "EXCHANGE", parse_command_apdu(data)
        if data.startswith("803c"):
            return "CONTROL FLOW", parse_command_apdu(data)
    
    # ----- RESPONSE -----
    if data.endswith("9000") or re.match(r'.*61[a-fA-F0-9]{2}$', data):
        # SELECT response
        if data.startswith(("5a", "5c", "d4")):
            return "SELECT response", parse_response_apdu(data)
        # SPAKE2+ REQUEST response (50h, 5Fh)
        elif data.startswith(("50", "5f")):
            return "SPAKE2+ REQUEST response", parse_response_apdu(data)
        # SPAKE2+ VERIFY response (58h)
        elif data.startswith("58"):
            return "SPAKE2+ VERIFY response", parse_response_apdu(data)
        # AUTH0 response
        elif data.startswith("86") or data.startswith("9d"):
            return "AUTH0 response", parse_response_apdu(data, is_auth0_resp=True)
        # AUTH1 response
        elif data.startswith("9e"):
            return "AUTH1 response", parse_response_apdu(data)
        elif prev_command_type is not None:
            if "AUTH0" in prev_command_type:
                return "AUTH0 response", parse_response_apdu(data)
            elif "AUTH1" in prev_command_type:
                return "AUTH1 response", parse_response_apdu(data)
            elif "WRITE DATA" in prev_command_type:
                return "WRITE DATA response", parse_response_apdu(data)
            elif "SPAKE2+ REQUEST" in prev_command_type:
                return "SPAKE2+ REQUEST response", parse_response_apdu(data)
            elif "SPAKE2+ VERIFY" in prev_command_type:
                return "SPAKE2+ VERIFY response", parse_response_apdu(data)
            elif "GET RESPONSE" in prev_command_type:
                return "GET RESPONSE response", parse_response_apdu(data)
            elif "GET DATA" in prev_command_type:
                return "GET DATA response", parse_response_apdu(data)
            elif "EXCHANGE" in prev_command_type:
                return "EXCHANGE response", parse_response_apdu(data)
            elif "CONTROL FLOW" in prev_command_type:
                return "CONTROL FLOW response", parse_response_apdu(data)
        return "UNKNOWN response", parse_response_apdu(data)
    return "UNKNOWN", {"payload": data, "command_mac": "", "response_mac": "", "status": ""}

def parse_auth0_payload(payload):
    fields = {}
    i = 0
    while i + 4 <= len(payload):  # 최소 tag+len+value(1byte) 이상일 때만
        tag = payload[i:i+2].lower()
        length = int(payload[i+2:i+4], 16) * 2  # hex length in bytes → string length
        value = payload[i:i+4+length]
        if tag == "5c":
            fields["protocol_version"] = value  # ex: 5c020100
        elif tag == "87":
            fields["vehicle_ePK"] = value
        elif tag == "4c":
            fields["transaction_identifier"] = value
        elif tag == "4d":
            fields["vehicle_identifier"] = value
        i += 4 + length
    return fields

def parse_spake2_verify_payload(payload):
    fields = {}
    i = 0
    while i + 4 <= len(payload):
        tag = payload[i:i+2].lower()
        length = int(payload[i+2:i+4], 16) * 2
        value = payload[i:i+4+length]
        if tag == "52":
            fields["curve_point_y"] = value
        elif tag == "57":
            fields["vehicle_evi_m1"] = value
        i += 4 + length
    return fields

def calculate_time_delta(prev_server_time, next_server_time):
    """
    이전 server 시간과 다음 server 시간의 차이를 계산 (ms)
    """
    if prev_server_time and next_server_time:
        try:
            prev_dt = datetime.strptime(prev_server_time, "%Y-%m-%d %H:%M:%S.%f")
            next_dt = datetime.strptime(next_server_time, "%Y-%m-%d %H:%M:%S.%f")
            delta = (next_dt - prev_dt).total_seconds() * 1000  # ms
            return f"{delta:.2f}ms"
        except Exception as e:
            return ""
    return ""

def get_output_filename(input_filename):
    base, ext = os.path.splitext(input_filename)
    return f"{base}_parsing.csv"

def print_header_box():
    table = Table(show_header=True, show_lines=True, pad_edge=False)
    for col, color in columns:
        table.add_column(f"[{color}]{col}[/{color}]")
    console.print(table)

    
def print_data_row(parsed):
    table = Table(show_header=True, show_lines=False, pad_edge=False)
    for col, color in columns:
        table.add_column(f"[{color}]{col}[/{color}]")
    table.add_row(
        f"[cyan]{parsed['timestamp']}[/cyan]",
        f"[bright_cyan]{parsed.get('time_delta','')}[/bright_cyan]",
        f"[bold yellow]{parsed['command_type']}[/bold yellow]",
        f"[green]{parsed.get('CLA','')}[/green]",
        f"[green]{parsed.get('INS','')}[/green]",
        f"[green]{parsed.get('P1','')}[/green]",
        f"[green]{parsed.get('P2','')}[/green]",
        f"[green]{parsed.get('Lc','')}[/green]",
        f"[magenta]{parsed.get('payload','')}[/magenta]",
        f"[white]{parsed.get('protocol_version','')}[/white]",
        f"[white]{parsed.get('vehicle_ePK','')}[/white]",
        f"[white]{parsed.get('transaction_identifier','')}[/white]",
        f"[white]{parsed.get('vehicle_identifier','')}[/white]",
        f"[white]{parsed.get('endpoint_ePK','')}[/white]",
        f"[white]{parsed.get('cryptogram','')}[/white]",
        f"[white]{parsed.get('curve_point_y','')}[/white]",
        f"[white]{parsed.get('vehicle_evi_m1','')}[/white]",
        f"[red]{parsed.get('command_mac','')}[/red]",
        f"[blue]{parsed.get('response_mac','')}[/blue]",
        f"[white]{parsed.get('status','')}[/white]",
    )
    console.print(table)


class RealtimeLogBuffer:
    """실시간 로그를 버퍼링하며 time_delta를 계산하는 클래스"""
    
    def __init__(self, buffer_size=30):
        self.buffer = deque(maxlen=buffer_size)
        self.pending_logs = deque()
        self.server_data_pattern = re.compile(
            r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+\[server\].*server data:"
        )
        self.publish_pattern = re.compile(
            r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+\[server\].*Publish reached"
        )
        self.log_pattern = re.compile(
            r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+\[log\].*?:.*?([0-9a-fA-F]{4,})\s*$"
        )
        self.prev_command_type = None
        
    def process_line(self, line):
        """라인을 처리하고, 출력 가능한 파싱된 데이터들을 반환"""
        self.buffer.append(line)
        output_list = []
        
        # [log] 라인인 경우
        log_match = self.log_pattern.search(line)
        if log_match:
            timestamp = log_match.group(1)
            data = log_match.group(2).lower()
            cmd_type, parsed = classify_and_parse_apdu(data, self.prev_command_type)
            parsed['timestamp'] = timestamp
            parsed['command_type'] = cmd_type
            
            # command인 경우 prev_command_type 갱신
            if cmd_type not in ["UNKNOWN", "CONTROL FLOW response"] and "response" not in cmd_type:
                self.prev_command_type = cmd_type
            
            # 이전 "server data:" 찾기
            prev_server_time = None
            buffer_list = list(self.buffer)
            current_idx = len(buffer_list) - 1
            
            for i in range(current_idx - 1, -1, -1):
                server_data_match = self.server_data_pattern.search(buffer_list[i])
                if server_data_match:
                    prev_server_time = server_data_match.group(1)
                    break
            
            # pending_logs에 추가 (아직 publish가 안 왔으므로)
            self.pending_logs.append({
                'parsed': parsed,
                'prev_server_time': prev_server_time,
            })
            
            # 너무 많이 쌓이면 오래된 것부터 강제 출력 (타임아웃)
            if len(self.pending_logs) > 20:
                oldest = self.pending_logs.popleft()
                oldest['parsed']['time_delta'] = "TIMEOUT"
                output_list.append(oldest['parsed'])
        
        # [server] Publish reached 라인인 경우
        publish_match = self.publish_pattern.search(line)
        if publish_match:
            publish_time = publish_match.group(1)
            
            # pending_logs의 모든 log에 대해 time_delta 계산 후 출력
            while self.pending_logs:
                log_data = self.pending_logs.popleft()
                prev_time = log_data['prev_server_time']
                time_delta = calculate_time_delta(prev_time, publish_time)
                log_data['parsed']['time_delta'] = time_delta
                output_list.append(log_data['parsed'])
        
        return output_list


def parse_stdin_realtime():
    """실시간 stdin 파싱 - Publish reached가 올 때까지 대기"""
    print_header_box()
    buffer = RealtimeLogBuffer(buffer_size=30)
    
    for line in sys.stdin:
        results = buffer.process_line(line)
        for result in results:
            print_data_row(result)


def main(input_filename, live_mode=False):
    if live_mode:
        import time
        print("timestamp,time_delta,command_type,CLA,INS,P1,P2,Lc,payload,command_mac,response_mac,status")
        with open(input_filename, 'r', encoding='utf-8', errors='ignore') as f:
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.2)
                    continue
                parse_and_print_line(line)
        return

    output_filename = get_output_filename(input_filename)
    
    # 패턴 정의
    server_data_pattern = re.compile(
        r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+\[server\].*server data:"
    )
    publish_pattern = re.compile(
        r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+\[server\].*Publish reached"
    )
    log_pattern = re.compile(
        r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+\[log\].*?:.*?([0-9a-fA-F]{4,})\s*$"
    )
    
    # 전체 라인 읽기
    all_lines = []
    with open(input_filename, 'r', encoding='utf-8', errors='ignore') as f:
        all_lines = f.readlines()
    
    results = []
    prev_command_type = None
    
    for i, line in enumerate(all_lines):
        log_match = log_pattern.search(line)
        if not log_match:
            continue
            
        timestamp = log_match.group(1)
        data = log_match.group(2).lower()
        cmd_type, parsed = classify_and_parse_apdu(data, prev_command_type)
        parsed['timestamp'] = timestamp
        parsed['command_type'] = cmd_type
        
        # time_delta 계산
        prev_server_time = None
        next_server_time = None
        
        # 이전 "server data:" 찾기
        for j in range(i-1, max(0, i-10), -1):
            server_data_match = server_data_pattern.search(all_lines[j])
            if server_data_match:
                prev_server_time = server_data_match.group(1)
                break
        
        # 다음 "Publish reached" 찾기
        for j in range(i+1, min(len(all_lines), i+10)):
            publish_match = publish_pattern.search(all_lines[j])
            if publish_match:
                next_server_time = publish_match.group(1)
                break
        
        parsed['time_delta'] = calculate_time_delta(prev_server_time, next_server_time)
        results.append(parsed)
        
        # command인 경우에만 prev_command_type 갱신
        if cmd_type not in ["UNKNOWN", "CONTROL FLOW response"] and "response" not in cmd_type:
            prev_command_type = cmd_type
    
    df = pd.DataFrame(results, dtype=str)
    cols = [
        "timestamp", "time_delta", "command_type", "CLA", "INS", "P1", "P2", "Lc",
        "payload", "protocol_version", "vehicle_ePK", "transaction_identifier", "vehicle_identifier", 
        "endpoint_ePK", "cryptogram",
        "curve_point_y", "vehicle_evi_m1",
        "command_mac", "response_mac", "status"
    ]
    cols = [c for c in cols if c in df.columns]
    df = df.reindex(columns=cols, fill_value='')

    df.to_csv(output_filename, index=False, na_rep='')
    print(f"Parsing complete! Saved as {output_filename}")


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "--stdin":
        parse_stdin_realtime()
    elif len(sys.argv) == 2:
        main(sys.argv[1])
    else:
        print("python parsing_NFC.py <log파일> 또는 python parsing_NFC.py --stdin")
        sys.exit(1)
