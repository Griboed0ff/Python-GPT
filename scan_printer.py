import time
import pandas as pd
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess
import ipaddress
import configparser
from pysnmp.hlapi import *
from sqlalchemy import create_engine


start_time = time.time()
config = configparser.ConfigParser()
config.read('/etc/zabbix/zabbix-python.conf')
# SNMP параметры
SNMP_PORT = 161
SNMP_COMMUNITY = 'gkj[jt50cjj,otcndj'
OID_MODEL = '1.3.6.1.2.1.25.3.2.1.3.1'
OID_SERIAL = '1.3.6.1.2.1.43.5.1.1.17.1'


def is_valid_subnet(subnet):
    try:
        ipaddress.ip_network(subnet, strict=False)
        return True
    except ValueError:
        return False


def get_data_from_dwh():
    dwh_username = config.get('dwh_db', 'dwh_db_user')
    dwh_password = config.get('dwh_db', 'dwh_db_password')
    dwh_database = config.get('dwh_db', 'dwh_db')
    dwh_url = f'oracle+cx_oracle://{dwh_username}:{dwh_password}@{dwh_database}'
    dwh_connection = create_engine(dwh_url)
    dwh_query = """SELECT z.IP_4118 AS ip_subnet, ct.atwtb, adr.sort2, st.TEXT_S
FROM sapsr3.t001w@sap_view            t1,
sapsr3.wrf1@sap_view             w,
sapsr3.t001k@sap_view            t2,
sapsr3.zmd_t001w@sap_view        z,
sapsr3.KLAH@sap_view             k,
sapsr3.swor@sap_view             s,
sapsr3.ZMD_IP_TEL_CISCO@sap_view c,
sapsr3.ZMD_ROUTER_CISCO@sap_view r,
sapsr3.ausp@sap_view             a,
sapsr3.cabn@sap_view             ca,
sapsr3.cawnt@sap_view            ct,
sapsr3.cawn@sap_view             cw,
sapsr3.ZMM_STATUS_OP@sap_view    st,
sapsr3.adrc@sap_view             adr
WHERE t1.mandt = '400'
and w.mandt = t1.mandt and t1.mandt = z.mandt and t1.werks = z.werks and t1.mandt = t2.mandt
and t1.bwkey = t2.bwkey and t1.kunnr = w.locnr and t2.bwmod = '2000' and w.schld = '00000000'
and t1.mandt = s.mandt and s.mandt = k.mandt and k.class = z.WH_DIVISION_MTS_7178 and k.klart = '035'
and s.clint = k.clint and s.spras = 'R' and t1.mandt = c.mandt(+) 
and z.IP_TELEFON_CISCO_4106 = c.IP_TELEFON_CISCO_4106(+)
and t1.mandt = c.mandt(+) and z.MARSHRUTIZATOR_CISCO_4111 = r.MARSHRUTIZATOR_CISCO_4111(+) and ca.mandt = a.mandt
and ca.mandt = t1.mandt and ca.mandt = ct.mandt and ca.mandt = cw.mandt and ca.atinn = a.atinn and a.mafid = 'O'
AND a.klart = '035' AND a.objek = t1.werks AND ca.atnam = 'ZS_M_REGION_MTS' and cw.atinn = ct.atinn 
AND cw.atzhl = ct.atzhl
AND cw.adzhl = ct.adzhl and cw.atinn = a.atinn AND cw.atwrt = a.atwrt AND ct.spras = 'R' AND ct.adzhl = '0000'
and st.mandt = t1.mandt and st.ZZSTATUS_OP = w.ZZSTATUS_OP and adr.CLIENT = t1.mandt and adr.ADDRNUMBER = t1.ADRNR"""
    dataframe = pd.read_sql(dwh_query, dwh_connection)
    valid_subnets_df = dataframe[dataframe['ip_subnet'].apply(is_valid_subnet)]
    return valid_subnets_df


def get_ip_range(subnet):
    network = ipaddress.ip_network(subnet, strict=False)
    return f"{network[0]}-{network[-1]}"


def scan_subnet(subnet):
    ip_range = get_ip_range(subnet)
    command = f"sudo masscan {ip_range} --ping --rate=300"
    scan_result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    active_ips = parse_output(scan_result.stdout)
    return subnet, active_ips


def parse_output(output):
    return [line.split()[-1] for line in output.decode('utf-8').split('\n') if 'Discovered open port' in line]


def scan_subnets(clean_subnets_df):
    active_ip_list = []
    with ThreadPoolExecutor(max_workers=70) as executor:
        futures = [executor.submit(scan_subnet, subnet) for subnet in clean_subnets_df['ip_subnet'].tolist()]
        for future in as_completed(futures):
            subnet_result, ips = future.result()
            for ip in ips:
                active_ip_list.append({'Subnet': subnet_result, 'Active_IP': ip})
    return pd.DataFrame(active_ip_list)


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

        errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

        if errorIndication:
            return None
        elif errorStatus:
            return None
        else:
            model = varBinds[0][1]
            serial = varBinds[1][1]
            return {'IP Address': host, 'Model': str(model), 'Serial Number': str(serial)}
    except Exception as e:
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

    printer_df = pd.DataFrame(results)
    return printer_df


dwh_subnets_df = get_data_from_dwh()
scan_results_df = scan_subnets(dwh_subnets_df)
print(scan_results_df)

if __name__ == "__main__":
    # Находим сетевые принтеры с помощью функции find_printers
    printers_df = find_printers(scan_results_df)
    print(printers_df)


end_time = time.time()
elapsed_time = (end_time - start_time) / 60
print(f"Elapsed time: {elapsed_time:.2f} minutes")
