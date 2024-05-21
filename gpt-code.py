import time
import pandas as pd
from concurrent.futures import ThreadPoolExecutor, as_completed
from pysnmp.hlapi import *
import subprocess
import ipaddress
import configparser
from sqlalchemy import create_engine
import logging

# Настройка логирования
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
start_time = time.time()
config = configparser.ConfigParser()
config.read('/etc/zabbix/zabbix-python.conf')
SNMP_COMMUNITY = "public"  # Замени на своё значение
SNMP_PORT = 161  # Замени на порт, используемый на твоём устройстве
OID_MODEL = "1.3.6.1.2.1.25.3.2.1.3.1"  # Замени на корректный OID
OID_SERIAL = "1.3.6.1.2.1.43.5.1.1.17.1"  # Замени на корректный OID


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
    iterator = getCmd(
        SnmpEngine(),
        CommunityData(SNMP_COMMUNITY, mpModel=0),  # SNMPv1
        UdpTransportTarget((host, SNMP_PORT), timeout=1, retries=1),
        ContextData(),
        ObjectType(ObjectIdentity(OID_MODEL)),
        ObjectType(ObjectIdentity(OID_SERIAL))
    )

    error_indication, error_status, error_index, var_binds = next(iterator)

    result = {}
    if error_indication:
        logging.error(f"Error on {host}: {error_indication}")
    elif error_status:
        logging.error('%s at %s' % (
            error_status.prettyPrint(),
            error_index and var_binds[int(error_index) - 1] or '?'
        ))
    else:
        for varBind in var_binds:
            oid, value = [x.prettyPrint() for x in varBind]
            result[oid] = value
        if result:
            result['IP'] = host

    logging.debug(f"Checked {host} in {time.time() - start_time:.2f} seconds")
    return result if result else None


def find_printers(df):
    """ Функция для поиска принтеров и сбора информации через SNMP """
    results = []
    max_workers = min(33000, len(df))  # Ограничиваем количество потоков разумным числом
    logging.info(f"Starting ThreadPoolExecutor with max_workers={max_workers}")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_snmp, row['Active_IP']): row['Active_IP'] for _, row in df.iterrows()}
        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as e:
                logging.error(f"Exception occurred: {e}")

    # Преобразование списка результатов в DataFrame
    printers_df_out = pd.DataFrame(results)

    if not printers_df_out.empty:
        # Обрезаем префиксы
        printers_df_out.columns = printers_df_out.columns.str.replace(r'SNMPv2-SMI::mib-2.', '', regex=True)

        # Переименуем столбцы
        printers_df_out.rename(columns={
            "25.3.2.1.3.1": 'model',
            "43.5.1.1.17.1": 'sn',
            'IP': 'ip'
        }, inplace=True)

    return printers_df_out


dwh_subnets_df = get_data_from_dwh()
scan_results_df = scan_subnets(dwh_subnets_df)
print(scan_results_df)

# Передаем правильный DataFrame в функцию find_printers
printers_df = find_printers(scan_results_df)


# Выводим DataFrame для проверки
print(printers_df)

end_time = time.time()
elapsed_time = (end_time - start_time) / 60
print(f"Elapsed time: {elapsed_time:.2f} minutes")
