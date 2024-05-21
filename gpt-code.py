import time
import ipaddress
import pandas as pd
from pysnmp.hlapi import SnmpEngine, CommunityData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity, getCmd
from concurrent.futures import ThreadPoolExecutor, as_completed

def scan_network(ip: str) -> pd.DataFrame:
    print(f'''\nScanning Network: {ip}''')
    from scapy.all import ARP, Ether, srp
    network = ip  # сетевой адрес
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=0)[0]

    clients = []
    for sent, received in result:
        clients.append({'Subnet': ip, 'Active_IP': received.psrc})

    df = pd.DataFrame(clients)
    if not df.empty:
        print(f"Active IP addresses on {ip}:")
        print(df.to_string(index=False))
    else:
        print(f"No active IPs found on {ip}")

    return df

networks = ['10.80.52.0/24', '10.80.49.0/24']
active_ips = pd.concat([scan_network(net) for net in networks], ignore_index=True)
print("Network scanning complete.")

SNMP_COMMUNITY = "gkj[jt50cjj,otcndj"  # Замени на своё значение
SNMP_PORT = 161  # Замени на порт, используемый на твоём устройстве
OID_MODEL = "1.3.6.1.2.1.1.1.0"  # Замени на корректный OID
OID_SERIAL = "1.3.6.1.2.1.1.2.0"  # Замени на корректный OID

def check_snmp(host):
    """ Проверяет значение SNMP на указанном хосте """
    try:
        iterator = getCmd(
            SnmpEngine(),
            CommunityData(SNMP_COMMUNITY, mpModel=0),
            UdpTransportTarget((host, SNMP_PORT)),
            ContextData(),
            ObjectType(ObjectIdentity(OID_MODEL)),
            ObjectType(ObjectIdentity(OID_SERIAL))
        )

        error_indication, error_status, error_index, var_binds = next(iterator)

        if error_indication:
            print(f"Error: {error_indication}")
            return None
        elif error_status:
            print(f"Error: {error_status.prettyPrint()}")
            return None
        else:
            model = var_binds[0][1]
            serial = var_binds[1][1]
            return {'IP Address': host, 'Model': str(model), 'Serial Number': str(serial)}

    except Exception as e:
        print(f"Exception: {e}")
        return None


def find_printers(df):
    """ Находит все сетевые принтеры среди доступных адресов """
    results = []
    with ThreadPoolExecutor(max_workers=256) as executor:
        futures = {executor.submit(check_snmp, row['Active_IP']): row['Active_IP'] for _, row in df.iterrows() if not row['Active_IP'].endswith('.1')}
        for future in as_completed(futures):
            result = future.result()
            if result:
                results.append(result)
    printers_df = pd.DataFrame(results)
    return printers_df

printers_df = find_printers(active_ips)
print(printers_df)
printers_df.to_csv('printers.csv', index=False) # сохр
