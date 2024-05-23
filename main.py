import pandas as pd
import concurrent.futures
import os
import json
import requests
import yaml
import ipaddress
from urllib.parse import urlparse

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

def read_conf_file(file_path):
    rows = []
    with open(file_path, 'r') as file:
        lines = file.readlines()
        for line in lines:
            if not line.startswith('#') and not line.isspace():
                parts = line.strip().split()
                if len(parts) == 2:
                    pattern, address = parts
                    rows.append({'pattern': pattern.strip(), 'address': address.strip(), 'other': None})
                elif len(parts) == 1:
                    address = parts[0]
                    if ',' in address:
                        pattern, address = address.split(',', 1)
                        rows.append({'pattern': pattern.strip(), 'address': address.strip(), 'other': None})
                    else:
                        rows.append({'pattern': 'DOMAIN', 'address': address.strip(), 'other': None})
    return pd.DataFrame(rows, columns=['pattern', 'address', 'other'])

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
    parsed_url = urlparse(link)
    if parsed_url.scheme in ('http', 'https'):
        if link.endswith('.yaml'):
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
                return pd.DataFrame(rows, columns=['pattern', 'address', 'other'])
            except:
                return read_list_from_url(link)
        elif link.endswith('.conf'):
            return read_conf_file(link)
        else:
            return read_list_from_url(link)
    else:
        if os.path.exists(link):
            if link.endswith('.yaml'):
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
                    return pd.DataFrame(rows, columns=['pattern', 'address', 'other'])
                except:
                    return read_list_from_url(link)
            elif link.endswith('.conf'):
                return read_conf_file(link)
            else:
                return read_list_from_url(link)
        else:
            print(f"File {link} does not exist.")
            return pd.DataFrame(columns=['pattern', 'address', 'other'])

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

    df = df[~df['pattern'].str.contains('#')].reset_index(drop=True)

    map_dict = {'DOMAIN-SUFFIX': 'domain_suffix', 'HOST-SUFFIX': 'domain_suffix', 'DOMAIN': 'domain', 'HOST': 'domain', 'host': 'domain',
                'DOMAIN-KEYWORD':'domain_keyword', 'HOST-KEYWORD': 'domain_keyword', 'host-keyword': 'domain_keyword', 'IP-CIDR': 'ip_cidr',
                'ip-cidr': 'ip_cidr', 'IP-CIDR6': 'ip_cidr', 
                'IP6-CIDR': 'ip_cidr','SRC-IP-CIDR': 'source_ip_cidr', 'GEOIP': 'geoip', 'DST-PORT': 'port',
                'SRC-PORT': 'source_port', "URL-REGEX": "domain_regex"}

    df = df[df['pattern'].isin(map_dict.keys())].reset_index(drop=True)
    df = df.drop_duplicates().reset_index(drop=True)
    df['pattern'] = df['pattern'].replace(map_dict)

    os.makedirs(output_directory, exist_ok=True)

    result_rules = {"version": 1, "rules": []}
    domain_entries = []

    for pattern, addresses in df.groupby('pattern')['address'].apply(list).to_dict().items():
        if pattern == 'domain_suffix':
            rule_entry = {pattern: ['.' + address.strip() for address in addresses]}
            result_rules["rules"].append(rule_entry)
            domain_entries.extend([address.strip() for address in addresses])
        elif pattern == 'domain':
            domain_entries.extend([address
