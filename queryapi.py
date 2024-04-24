'''

* * * This Script is an API to query from PostgreSQL database to retrieve your scandata. * * * 

* * * Make sure to configure the config dictionary to match your PostgreSQL db configutations. * * *

Required Libraries: 

Flask - version 2.2.5
psycopg2 - version 2.9.9

'''

from flask import Flask, request, jsonify
from psycopg2 import connect

app = Flask(__name__)

# PostgreSQL configuration
db_config = {
    'host': 'your_database_ip/hostname',
    'database': 'your _database_name',
    'user': 'your_username',
    'password': 'your_secret_password',
    'port': 'your_port (Postgres uses 5432 by default)'
}

def format_scan_result(row):
    return f"{row[4]}/{row[5]} {row[6]:<30} {row[3].strftime('%H:%M:%S')}"

@app.route('/api/scans', methods=['GET'])
def get_scans():
    clientname = request.args.get('clientname')
    ip = request.args.get('ip')

    if not clientname and not ip:
        return 'Provide either clientname or ip parameter', 400

    try:
        conn = connect(**db_config)
        cur = conn.cursor()

        if clientname:
            query = f'SELECT * FROM scans WHERE clientname = \'{clientname}\' ORDER BY date DESC, time DESC'
        else:
            query = f'SELECT * FROM scans WHERE ip = \'{ip}\' ORDER BY date DESC, time DESC'
        
        cur.execute(query)
        rows = cur.fetchall()

        if rows:
            results = [format_scan_result(row) for row in rows]
            response_text = ' '.join(results)
            return jsonify(result=response_text), 200
        else:
            return 'No scans found for the provided clientname or IP', 404
    
    except Exception as e:
        return str(e), 500

if __name__ == '__main__':
    app.run(debug=False)
