import pandas as pd
import concurrent.futures
import os
import json
import requests
import yaml
import ipaddress

def read_yaml_from_url(url):
    response = requests.get(url)
    response.raise_for_status()  # Raise an HTTPError for bad responses
    yaml_data = yaml.safe_load(response.text)
    return yaml_data

def read_list_from_url(url):
    df = pd.read_csv(url, header=None, names=['pattern', 'address', 'other', 'other2', 'other3'])
    filtered_rows = []
    for index, row in df.iterrows():
        if 'AND' not in row['pattern']:
            filtered_rows.append(row)
    df_filtered = pd.DataFrame(filtered_rows, columns=['pattern', 'address', 'other', 'other2', 'other3'])
    return df_filtered

def read_conf_from_url(url):
    response = requests.get(url)
    response.raise_for_status()
    lines = response.text.splitlines()
    rows = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split()
        if len(parts) >= 2:
            pattern = parts[0]
            address = parts[1]
            other = " ".join(parts[2:]) if len(parts) > 2 else None
            rows.append({'pattern': pattern, 'address': address, 'other': other})
    if not rows:
        print(f"No valid rows found in conf file from {url}")
    df = pd.DataFrame(rows, columns=['pattern', 'address', 'other'])
    print(f"DataFrame from conf file {url}:\n{df}")
    return df

def read_list_from_text(url):
    response = requests.get(url)
    response.raise_for_status()
    lines = response.text.splitlines()
    rows = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split()
        if len(parts) >= 2:
            pattern = parts[0]
            address = parts[1]
            other = " ".join(parts[2:]) if len(parts) > 2 else None
            rows.append({'pattern': pattern, 'address': address, 'other': other})
    if not rows:
        print(f"No valid rows found in list file from {url}")
    df = pd.DataFrame(rows, columns=['pattern', 'address', 'other'])
    print(f"DataFrame from list file {url}:\n{df}")
    return df

def is_ipv4_or_ipv6(address):
    try:
        ipaddress.IPv4Network(address)
        return 'ipv4'
    except ValueError:
        try:
            ipaddress.IPv6Network(address)
            return 'ipv6'
        except ValueError:
            return None

def parse_and_convert_to_dataframe(link):
    print(f"Processing file: {link}")
    if link.endswith('.yaml') or link.endswith('.txt'):
        try:
            yaml_data = read_yaml_from_url(link)
            rows = []
            if not isinstance(yaml_data, str):
                items = yaml_data.get('payload', [])
            else:
                lines = yaml_data.splitlines()
                line_content = lines[0]
                items = line_content.split()
            for item in items:
                address = item.strip("'")
                if ',' not in item:
                    if is_ipv4_or_ipv6(item):
                        pattern = 'IP-CIDR'
                    else:
                        if address.startswith('+') or address.startswith('.'):
                            pattern = 'DOMAIN-SUFFIX'
                            address = address[1:]
                            if address.startswith('.'):
                                address = address[1:]
                        else:
                            pattern = 'DOMAIN'
                else:
                    pattern, address = item.split(',', 1)
                rows.append({'pattern': pattern.strip(), 'address': address.strip(), 'other': None})
            df = pd.DataFrame(rows, columns=['pattern', 'address', 'other'])
            print(f"DataFrame from yaml/txt file {link}:\n{df}")
        except Exception as e:
            print(f"Error reading yaml or txt file {link}: {e}")
            df = read_list_from_url(link)
    elif link.endswith('.csv'):
        df = read_list_from_url(link)
        print(f"DataFrame from csv file {link}:\n{df}")
    elif link.endswith('.conf'):
        df = read_conf_from_url(link)
    elif link.endswith('.list'):
        df = read_list_from_text(link)
    else:
        raise ValueError(f"Unsupported file type: {link}")
    return df

def sort_dict(obj):
    if isinstance(obj, dict):
        return {k: sort_dict(obj[k]) for k in sorted(obj)}
    elif isinstance(obj, list) and all(isinstance(elem, dict) for elem in obj):
        return sorted([sort_dict(x) for x in obj], key=lambda d: sorted(d.keys())[0])
    elif isinstance(obj, list):
        return sorted(sort_dict(x) for x in obj)
    else:
        return obj

def parse_list_file(link, output_directory):
    with concurrent.futures.ThreadPoolExecutor() as executor:
        results = list(executor.map(parse_and_convert_to_dataframe, [link]))
        df = pd.concat(results, ignore_index=True)

    if df.empty:
        print(f"No valid data found in file from {link}")
        return None

    print(f"Initial DataFrame from file {link}:\n{df}")

    df = df[~df['pattern'].str.contains('#')].reset_index(drop=True)

    map_dict = {'DOMAIN-SUFFIX': 'domain_suffix', 'HOST-SUFFIX': 'domain_suffix', 'DOMAIN': 'domain', 'HOST': 'domain', 'host': 'domain',
                'DOMAIN-KEYWORD':'domain_keyword', 'HOST-KEYWORD': 'domain_keyword', 'host-keyword': 'domain_keyword', 'IP-CIDR': 'ip_cidr',
                'ip-cidr': 'ip_cidr', 'IP-CIDR6': 'ip_cidr', 
                'IP6-CIDR': 'ip_cidr','SRC-IP-CIDR': 'source_ip_cidr', 'GEOIP': 'geoip', 'DST-PORT': 'port',
                'SRC-PORT': 'source_port', "URL-REGEX": "domain_regex"}

    df = df[df['pattern'].isin(map_dict.keys())].reset_index(drop=True)

    df = df.drop_duplicates().reset_index(drop=True)
    df['pattern'] = df['pattern'].replace(map_dict)

    print(f"Filtered and mapped DataFrame from file {link}:\n{df}")

    os.makedirs(output_directory, exist_ok=True)

    result_rules = {"version": 1, "rules": []}
    domain_entries = []

    for pattern, addresses in df.groupby('pattern')['address'].apply(list).to_dict().items():
        if pattern == 'domain_suffix':
            rule_entry = {pattern: ['.' + address.strip() for address in addresses]}
            result_rules["rules"].append(rule_entry)
            domain_entries.extend([address.strip() for address in addresses])
        elif pattern == 'domain':
            domain_entries.extend([address.strip() for address in addresses])
        else:
            rule_entry = {pattern: [address.strip() for address in addresses]}
            result_rules["rules"].append(rule_entry)

    domain_entries = list(set(domain_entries))
    if domain_entries:
        result_rules["rules"].insert(0, {'domain': domain_entries})

    file_name = os.path.join(output_directory, f"{os.path.basename(link).split('.')[0]}.json")
    with open(file_name, 'w', encoding='utf-8') as output_file:
        json.dump(sort_dict(result_rules), output_file, ensure_ascii=False, indent=2)

    srs_path = file_name.replace(".json", ".srs")
    os.system(f"sing-box rule-set compile --output {srs_path} {file_name}")
    return file_name

with open("../links.txt", 'r') as links_file:
    links = links_file.read().splitlines()

links = [l for l in links if l.strip() and not l.strip().startswith("#")]

output_dir = "./"
result_file_names = []

for link in links:
    result_file_name = parse_list_file(link, output_directory=output_dir)
    if result_file_name:
        result_file_names.append(result_file_name)

# 打印生成的文件名
for file_name in result_file_names:
    print(file_name)
