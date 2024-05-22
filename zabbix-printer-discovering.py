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


async def get_snmp_data(ip_address):
    async with semaphore:
        result = await get(
            SnmpEngine(),
            CommunityData(SNMP_COMMUNITY),
            UdpTransportTarget((ip_address, SNMP_PORT)),
            ContextData(),
            ObjectType(ObjectIdentity(OID_MODEL)),
            ObjectType(ObjectIdentity(OID_SERIAL)),
        )
        error_indication, error_status, error_index, var_binds = result
        if error_indication:
            logging.error(f"Error in SNMP request: {error_indication}")
            return None, None
        elif error_status:
            logging.error(f"Error in SNMP status: {error_status}")
            return None, None
        else:
            model = var_binds[0][1].prettyPrint().decode('utf-8')
            serial = var_binds[1][1].prettyPrint().decode('utf-8')
            return model, serial


async def get_all_snmp_data(active_ips):
    loop = asyncio.get_running_loop()
    with ThreadPoolExecutor() as pool:
        tasks = [
            loop.run_in_executor(
                pool, get_snmp_data, ip_address
            )
            for ip_address in active_ips
        ]
        results = await asyncio.gather(*tasks)
    return results


def main():
    valid_subnets_df = get_data_from_dwh()
    subnets = valid_subnets_df['ip_subnet'].tolist()

    with ThreadPoolExecutor(max_workers=70) as pool:
        scan_results = list(pool.map(scan_subnet, subnets))

    active_ips = []
    for subnet, ips in scan_results:
        active_ips.extend(ips)

    loop = asyncio.get_event_loop()
    snmp_results = loop.run_until_complete(get_all_snmp_data(active_ips))

    for model, serial in snmp_results:
        print(f"Model: {model}, Serial: {serial}")


if __name__ == "__main__":
    main()
