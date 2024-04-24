'''

* * * This Script does a port scan and stores the data to a PostgreSQL database.        * * * 

* * * Make sure to configure the config set to match your PostgreSQL db configutations. * * *

Required Libraries: 
psycopg2 - version 2.9.9
python-nmap - version 0.7.1

Requires nmap to be installed on the system.

'''

import psycopg2,time, sys, asyncio
from nmap import PortScanner
from multiprocessing import pool

from datetime import datetime
# config = {}
# with open("config.txt") as f:
# 	config = f.readlines()
config = {
    'host': '127.0.0.1',
    'database': 'nmap',
    'user': 'ekko',
    'password': 'user123',
    'port': '5432'
    }

# Configure the interval minutes between each scan.
minutes = 10

allscans_table = 'scans'
changescans_table = 'changes'

table_query = [f"CREATE TABLE IF NOT EXISTS {allscans_table} \
               (clientname VARCHAR(50)\
               ,ip VARCHAR(20), \
               date DATE NOT NULL, \
               time TIME NOT NULL, \
               port VARCHAR(10), \
               state VARCHAR(10), \
               service VARCHAR(50))",
               f"CREATE TABLE IF NOT EXISTS {changescans_table} \
                (clientname VARCHAR(50)\
               ,ip VARCHAR(20), \
               date DATE NOT NULL, \
               time TIME NOT NULL, \
               change VARCHAR(100))"]
iterator = 0
while True:
    try:
    
        conn = psycopg2.connect(**config)
        cur = conn.cursor()
        print(f'Connection to {config["database"]} Successful!')
        time.sleep(2)
        for q in table_query:
            cur.execute(q)
            conn.commit()  
        break  

    except Exception as e:

        print(f'\nError: {e}', end = '')
        time.sleep(1)
        print('Retrying in 5 secs...')
        time.sleep(4)
        iterator = iterator + 1
        if iterator == 4:
            print('\nConnection to Database Failed!!!\n\nTERMINATING NOW...')
            time.sleep(3)
            sys.exit(0)

nm = PortScanner()

# Nmap argument and target. By default it does an all port scan. 
arg = '-Pn -p-'

#enter your ip

target = input("Enter IP: ")
# target '192.168.100.177'

def entry_exists(host,date,port,protocol,state,service,time):
        
        cur.execute(f"SELECT * FROM {allscans_table} WHERE ip=%s AND date=%s AND port=%s AND time=%s\
                    ORDER BY date DESC, time DESC LIMIT 1",(host, date, f'{port}/{protocol}',time))
        last_entry = cur.fetchone()
        
        if last_entry:
            if last_entry[-1] == service and last_entry[-2] == state:
                return True
        return False

def First_run():

    cur.execute(f'SELECT * FROM {allscans_table}')
    result = cur.fetchall()
    if result:
        return False
    else:
        return True

async def perform_scan():

    print('Performing Scan...')
    nm.scan(target , arguments = arg)
    global p_time

    timestr = nm.scanstats()['timestr']
    parsed_time = datetime.strptime(timestr, "%a %b %d %H:%M:%S %Y")
    
    d = parsed_time.date()
    t = parsed_time.time()

    c_state = 'closed'
    c_service = 'closed'

    runflag = First_run()

    for hosts in nm.all_hosts():

        for protocol in nm[target].all_protocols():
            
            p = sorted(nm[target][protocol].keys())
            
            for ports in p:
                
                s = nm[hosts][protocol][ports]['state']
                n = nm[hosts][protocol][ports]['name']
                
                if runflag:
                    query = f"INSERT INTO {changescans_table} (clientname,ip,date,time,change) \
                        VALUES (\'{nm[hosts].hostname()}\', \'{hosts}\', \'{d}\', \'{t}\', \
                        \'{ports}/{protocol}: {c_state}->{s}, {c_service}->{n}\')"
                    cur.execute(query)
                    conn.commit()
                
                if "p_time" in globals():
                
                    if not entry_exists(hosts, d, ports, protocol, s, n,p_time):
                    
                        cur.execute(f"SELECT * FROM {allscans_table} WHERE ip=%s AND date=%s AND port=%s AND time=%s\
                        ORDER BY date DESC, time DESC LIMIT 1",(hosts, d, f'{ports}/{protocol}',p_time))
                        lq = cur.fetchone()

                        if lq:
                            c_state = lq[-2]
                            c_service = lq[-1]

                        query = f"INSERT INTO {changescans_table} (clientname,ip,date,time,change) \
                        VALUES (\'{nm[hosts].hostname()}\', \'{hosts}\', \'{d}\', \'{t}\', \
                        \'{ports}/{protocol}: {c_state}->{s}, {c_service}->{n}\')"

                        cur.execute(query)
                        conn.commit()

                query = f"INSERT INTO {allscans_table} (clientname,ip,date,time,port,state,service) \
                VALUES (\'{nm[hosts].hostname()}\', \'{hosts}\', \'{d}\', \'{t}\', \'{ports}/{protocol}\', \'{s}\', \'{n}\')"
                cur.execute(query)
                conn.commit()
    p_time = t
    print("Scan complete")
    closed_connections(t)
    show_db(t)

def closed_connections(time):

    cur.execute(f"SELECT * FROM {changescans_table} WHERE change LIKE \'%closed->%\' ORDER BY date DESC, time DESC")
    ch_table = cur.fetchall()

    for results in ch_table:
        
        change = results[4].split(':')
        port = change[0].split('/')
        protocol = port[1]
        port = port[0]
        state = results[4].split('->')
        state = state[1].split(',')[0]
        service = results[4].split('->')[2]

        if not entry_exists(results[1],results[2],port,protocol,state,service,time):

            cur.execute(f'SELECT * FROM {changescans_table} WHERE ip=\'{results[1]}\' AND date=\'{results[2]}\' \
                        AND change like \'%{port}/{protocol}%\' ORDER BY date DESC, time DESC LIMIT 1')
            temp = cur.fetchone()
            
            if 'closed->' in temp[4]:
                query = f"INSERT INTO {changescans_table} (clientname,ip,date,time,change) \
                VALUES (\'{results[0]}\', \'{results[1]}\', \'{results[2]}\', \'{time}\', \
                \'{port}/{protocol}: {state}->closed, {service}->closed\')"
            
                cur.execute(query)
                conn.commit()

def show_db(time):
    query = f"SELECT * FROM {allscans_table} where time = \'{time}\' ORDER BY date DESC, time DESC"
    cur.execute(query)
    rows = cur.fetchall()
    for row in rows:
        print(row)

while True:
    try:
        asyncio.run(perform_scan())
        time.sleep(minutes*60)
    
    except KeyboardInterrupt:
        print('Terminating...')
        sys.exit(0)
