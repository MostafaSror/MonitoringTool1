from .models import Database, Configuration
from .InfraUtilities import OracleConnection, MongoConnection


database_mongodb = Configuration.objects.get(key='database_mongodb').value
database_used_type = Configuration.objects.get(key='database_used_type').value
mongoDB = MongoConnection(database_mongodb)


def ACH_accounts_job_checker():

    databases = Database.objects.filter(name__in=['PROD-Acceptance-SOF'])
    for db in databases:
        db_conn = OracleConnection(db.IP, db.port, db.service_name, db.user, db.password)
        if type(db_conn) is not str:
            with db_conn.cursor() as db_conn_cursor:
                query = """select count(acc.code)
                        from pos_sof.accounts acc 
                        left outer join POS_SOF.terminal_status_lookup ts on ts.id = acc.terminal_status_id
                        left outer join pos_sof.accounts acc1 on acc1.id = acc.primary_acct_id
                        left outer join pos_sof.accounts acc2 on acc2.id = acc.transform_from_acct_id
                        where
                        acc.account_type_id = 551
                        and acc.week_cycle_days is not null
                        and acc.next_transfer_run_date = TO_CHAR(current_date,'DD-Mon-YYYY')
                        and acc.terminal_status_id = 1
                        and acc2.balance > 0
                        and acc2.last_modification_date > TO_CHAR(current_date -1 ,'DD-Mon-YYYY')"""

                db_conn_cursor.execute(query)
                while True:
                    db_row = db_conn_cursor.fetchall()
                    if len(db_row) > 0:
                        print(db_row)
                        break
                    break

                mongoDB.achjob.insert_one({
                    "database": databaseName,
                    "creation_date": datetime.datetime.now(),
                    "jobName": 'ACH_accounts_job_checker',
                    "count": db_row[0][0]
                })
    return

def ACH_success_accounts_job_checker():
    databaseName = 'PROD-Acceptance-SOF'
    databases = Database.objects.filter(name__in=[databaseName])
    for db in databases:
        db_conn = OracleConnection(db.IP, db.port, db.service_name, db.user, db.password)
        if type(db_conn) is not str:
            with db_conn.cursor() as db_conn_cursor:
                query = """select count(*)
                        from pos_sof.accounts acc 
                        left outer join POS_SOF.terminal_status_lookup ts on ts.id = acc.terminal_status_id
                        left outer join pos_sof.accounts acc1 on acc1.id = acc.primary_acct_id
                        left outer join pos_sof.accounts acc2 on acc2.id = acc.transform_from_acct_id
                        where
                        acc.account_type_id = 551
                        and acc.week_cycle_days is not null
                        and acc.last_transfer_date = TO_CHAR(current_date,'DD-Mon-YYYY')
                        and acc.terminal_status_id = 1
                        and acc.balance > 0
                        and acc.last_modification_date > TO_CHAR(current_date,'DD-Mon-YYYY')"""

                db_conn_cursor.execute(query)
                while True:
                    db_row = db_conn_cursor.fetchall()
                    if len(db_row) > 0:
                        print(db_row)
                        break
                    break

                mongoDB.achjob.insert_one({
                    "database": databaseName,
                    "creation_date": datetime.datetime.now(),
                    "jobName": 'ACH_success_accounts_job_checker',
                    "count": db_row[0][0]
                })
    return
