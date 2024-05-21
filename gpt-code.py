import pandas as pd
import ipaddress
import configparser
from sqlalchemy import create_engine
import logging
import asyncio
from pysnmp.hlapi.asyncio import *
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess
import time

# Настройка логирования
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Чтение конфигурационного файла
config = configparser.ConfigParser()
config.read('/etc/zabbix/zabbix-python.conf')

# Константы SNMP
SNMP_COMMUNITY = "public"  # Замените на ваше значение
SNMP_PORT = 161  # Замените на порт, используемый на вашем устройстве
OID_MODEL = "1.3.6.1.2.1.25.3.2.1.3.1"  # Замените на корректный OID
OID_SERIAL = "1.3.6.1.2.1.43.5.1.1.17.1"  # Замените на корректный OID

# Максимальное количество одновременно работающих SNMP запросов
MAX_SNMP_REQUESTS = 2000

# Semaphore для ограничения количества одновременно выполняемых SNMP-запросов
semaphore = asyncio.Semaphore(MAX_SNMP_REQUESTS)  # Используем asyncio.Semaphore вместо threading.Semaphore


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
and st.mandt = t1.mandt and st.ZZSTATUS_OP = w.ZZSTATUS_OP and adr.CLIENT = t1.mandt and adr.ADDRNUMBER = t1.ADRNR
and rownum < 50"""
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


async def poll_snmp(ip):
    async with semaphore:
        error_indication, error_status, error_index, var_binds = await getCmd(
            SnmpEngine(),
            CommunityData(SNMP_COMMUNITY),
            UdpTransportTarget((ip, SNMP_PORT)),
            ContextData(),
            ObjectType(ObjectIdentity(OID_MODEL)),
            ObjectType(ObjectIdentity(OID_SERIAL))
        )

        if error_indication:
            return None
        elif error_status:
            return None
        else:
            model = str(var_binds[0][1]) if len(var_binds) > 0 else None
            serial = str(var_binds[1][1]) if len(var_binds) > 1 else None
            return ip, model, serial


async def find_printers(df):
    tasks = [poll_snmp(row['Active_IP']) for index, row in df.iterrows()]
    results = await asyncio.gather(*tasks)
    printers = [{'IP': res[0], 'Model': res[1], 'Serial': res[2]} for res in results if res]
    return pd.DataFrame(printers)


def main():
    start_time = time.time()
    clean_subnets_df = get_data_from_dwh()
    active_ips_df = scan_subnets(clean_subnets_df)
    print(active_ips_df)
    loop = asyncio.get_event_loop()
    printers_df = loop.run_until_complete(find_printers(active_ips_df))

    print(printers_df)

    end_time = time.time()
    logging.info(f"Время выполнения: {end_time - start_time} секунд")


if __name__ == '__main__':
    main()
