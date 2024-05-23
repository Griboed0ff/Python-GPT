import pandas as pd
import asyncio
import aiosnmp
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import cx_Oracle
from sqlalchemy import create_engine
import subprocess
import ipaddress
import configparser

# Настройка логирования
# logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
start_time = time.time()
config = configparser.ConfigParser()
config.read('/data/data/0001rtczabprx01/zabbix-printer-discovering/zabbix-python.conf')


def is_valid_subnet(subnet):
    try:
        ipaddress.ip_network(subnet, strict=False)
        return True
    except ValueError:
        return False


def get_data_from_dwh():
    try:
        dwh_username = config.get('dwh_db', 'dwh_db_user')
        dwh_password = config.get('dwh_db', 'dwh_db_password')
        dwh_host = config.get('dwh_db', 'dwh_db_host')
        dwh_port = config.get('dwh_db', 'dwh_db_port')
        dwh_service = config.get('dwh_db', 'dwh_db_service')
        dsn = f"(DESCRIPTION=(ADDRESS_LIST=(ADDRESS=(PROTOCOL=TCP)(HOST={dwh_host})(PORT={dwh_port})))(CONNECT_DATA=(SERVICE_NAME={dwh_service})))"
        dwh_url = f"oracle+cx_oracle://{dwh_username}:{dwh_password}@{dsn}"
        engine = create_engine(dwh_url)
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
        # Выполнить запрос к базе данных
        dataframe = pd.read_sql(dwh_query, engine)
        # Фильтровать допустимые подсети
        valid_subnets_df = dataframe[dataframe['ip_subnet'].apply(is_valid_subnet)]
        return valid_subnets_df
    except Exception as e:
        # logging.error(f"Failed to get data from DWH. Error: {e}")
        return pd.DataFrame()  # Возвращает пустой DataFrame при ошибке


def get_ip_range(subnet):
    network = ipaddress.ip_network(subnet, strict=False)
    return f"{network[0]}-{network[-1]}"


def scan_subnet(subnet):
    ip_range = get_ip_range(subnet)
    command = f"sudo masscan {ip_range} -p161,9100 --rate=300"
    scan_result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    active_ips = parse_output(scan_result.stdout)
    return subnet, active_ips


def parse_output(output):
    return [line.split()[-1] for line in output.decode('utf-8').split('\n') if 'Discovered open port' in line]


def scan_subnets(clean_subnets_df, max_workers=70):
    active_ip_list = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(scan_subnet, subnet) for subnet in clean_subnets_df['ip_subnet'].tolist()]
        for future in as_completed(futures):
            try:
                subnet_result, ips = future.result()
                for ip in ips:
                    active_ip_list.append({'Subnet': subnet_result, 'Active_IP': ip})
            except Exception:
                continue
    return pd.DataFrame(active_ip_list)


async def snmp_get(ip, oid, community='public', timeout=10):
    try:
        async with aiosnmp.Snmp(host=ip, community=community, port=161, timeout=timeout) as snmp:
            result = await snmp.get(oid)
            if result:
                value = result[0].value
                return value.decode('utf-8') if isinstance(value, bytes) else value
            else:
                return None
    except asyncio.TimeoutError:
        return None
    except Exception:
        return None


async def get_printer_info(ip):
    model_oid = '1.3.6.1.2.1.25.3.2.1.3.1'
    serial_oid = '1.3.6.1.2.1.43.5.1.1.17.1'
    try:
        model = await snmp_get(ip, model_oid)
        serial = await snmp_get(ip, serial_oid)
        if model and serial:
            return model, serial
        else:
            return None, None
    except Exception:
        return None, None


# Асинхронная функция для получения информации о принтерах по IP-адресам
async def get_printer_info_async(printer_ips):
    tasks = [asyncio.create_task(get_printer_info(ip)) for ip in printer_ips]
    results = await asyncio.gather(*tasks)
    return {ip: result for ip, result in zip(printer_ips, results)}


# Модифицированная функция для асинхронного опроса принтеров и сохранения результатов в DataFrame
async def discover_printers(active_ips_df):
    printer_ips = active_ips_df['Active_IP'].tolist()
    printer_info = await get_printer_info_async(printer_ips)

    printer_info_list = []
    for printer_ip, (model, serial) in printer_info.items():
        if model and serial:
            printer_info_list.append({'IP': printer_ip, 'Model': model, 'Serial': serial})

    return pd.DataFrame(printer_info_list)

if __name__ == '__main__':
    start_time = time.time()

    dwh_subnets_df = get_data_from_dwh()
    scan_results_df = scan_subnets(dwh_subnets_df)
    print(scan_results_df)

    try:
        printer_info_df = asyncio.run(discover_printers(scan_results_df))
        # Печатаем только конечный датафрейм
        print(printer_info_df)
    except Exception:
        pass

    end_time = time.time()
    elapsed_time = (end_time - start_time) / 60
    # print(f"Elapsed time: {elapsed_time:.2f} minutes")
