import pymongo

from .models import Exceptions, ExceptionsMonitor, RequestsMonitor, QueriesMonitor, Server, Configuration
from .InfraUtilities import MongoConnection, send_mail, OracleConnection
from .WebsphereTasks import getQueuesCounts

import json

import time
import datetime
import traceback


database_mongodb = Configuration.objects.get(key='database_mongodb').value
database_used_type = Configuration.objects.get(key='database_used_type').value
mongoDB = MongoConnection(database_mongodb)


def addExceptionMonitorRecord(ex_name, group, server, count, time):
    enable_monitoring = Configuration.objects.get(key='enable_monitoring').value
    if enable_monitoring == 'false':
        return

    exception_bycomponent = Exceptions.objects.filter(Code=ex_name,
                                                      AppComponentType__ComponentTypeCode=group.AppComponentTypeCode,
                                                      Group__groupName=None).first()
    exception_bygroup = Exceptions.objects.filter(Code=ex_name,
                                                  Group__groupName=group.groupName,
                                                  AppComponentType__ComponentTypeCode=None).first()

    if exception_bycomponent == None:
        if database_used_type == 'sqlite':

            counterObject = ExceptionsMonitor(
                Exception_id=exception_bygroup,
                server_id=server,
                count=count,
                lastAlertTime=time
            )
            counterObject.save()
        elif database_used_type == 'mongodb':
            mongoDB.exceptions.insert_one({
                "Exception_id": ex_name,
                "group": group.groupName,
                "server_id": server.IP,
                "count":count,
                "lastAlertTime": time
            })

    elif exception_bygroup == None:
        if database_used_type == 'sqlite':
            counterObject = ExceptionsMonitor(
                Exception_id=exception_bycomponent,
                server_id=server,
                count=count,
                lastAlertTime=time
            )
            counterObject.save()
        elif database_used_type == 'mongodb':
            mongoDB.exceptions.insert_one({
                "Exception_id": ex_name,
                "group": group.groupName,
                "server_id": server.IP,
                "count": count,
                "lastAlertTime": time
            })


def addRequestMonitorRecord(request, group, ip, time , failure):
    enable_monitoring = Configuration.objects.get(key='enable_monitoring').value
    if enable_monitoring == 'false':
        return
    if database_used_type == 'sqlite':
        reqCounter = RequestsMonitor.objects.filter(request_id__id=request.id, server_id__IP=ip).first()
        server = Server.objects.get(IP=ip)
        if reqCounter is None:
            counterObj = RequestsMonitor(
                request_id=request,
                group_id=group,
                server_id=server,
                counter=1,
            )
            counterObj.save()
        else:
            reqCounter.counter = reqCounter.counter + 1
            reqCounter.save()

            if reqCounter.counter > 3:
                send_mail(request.name, request.uri, ip, '0', '0',
                          "alert",
                          'moustafa.mamdouh@fawry.com', 'api')
                reqCounter.counter = 0
                reqCounter.save()

    elif database_used_type == 'mongodb':
        mongoDB.requests.insert_one({
            "request": request.name,
            "error": failure,
            "group": group,
            "server": ip,
            "lastAlertTime": time
        })


def get_query_result(database, q, check_time):
    if database.sid is not None:
        conn_str = database.sid
    else:
        conn_str = database.service_name

    if database.db_type == 'oracle':
        now = datetime.datetime.now()
        now = now - datetime.timedelta(minutes=q.timer)
        current_time = now.strftime("%d-%b-%Y %I:%M:%S.00000000 %p")
        passed = now - datetime.timedelta(minutes=q.timer)
        old_time = passed.strftime("%d-%b-%Y %I:%M:%S.00000000 %p")

        print("Current Time =", current_time)
        print("Current Time =", old_time)
        query_string = q.query.format(old_time, current_time)

    elif database.db_type == 'db2':
        now = datetime.datetime.now()
        now = now - datetime.timedelta(minutes=5)
        current_time = now.strftime("%Y-%M-%d %H:%M:%S.00000000")
        passed = now - datetime.timedelta(minutes=5)
        old_time = passed.strftime("%Y-%M-%d %H:%M:%S.00000000")

        print("Current Time =", current_time)
        print("Current Time =", old_time)
        query_string = q.query.format(old_time, current_time)

    elif database.db_type == 'sqlserver':
        now = datetime.datetime.now()
        now = now - datetime.timedelta(minutes=5)
        current_time = now.strftime("%d-%b-%Y %I:%M:%S.00000000 %p")
        passed = now - datetime.timedelta(minutes=5)
        old_time = passed.strftime("%d-%b-%Y %I:%M:%S.00000000 %p")

        print("Current Time =", current_time)
        print("Current Time =", old_time)
        query_string = q.query.format(old_time, current_time)

    try:
            db_conn = OracleConnection(database.IP, database.port, conn_str, database.user, database.password)
            with db_conn.cursor() as db_conn_cursor:
                query_rows = []
                db_conn_cursor.execute(query_string)
                while True:
                    db_row = db_conn_cursor.fetchone()
                    if db_row is None:
                        break
                    query_rows.append(db_row)

                    addQueriesMonitorRecord(query_rows, q, database, check_time)

                if q.nature == 'incremental':
                    if int(q.WarningThreshold) < result < int(q.Threshold):
                        send_mail(query_string, q.description, database.name, query_rows[0][0], q.Threshold,
                                  q.ExceptionSeverity,
                                  'moustafa.mamdouh@fawry.com , ' + q.recepients_warning, 'db')
                    elif result > int(q.Threshold):
                        send_mail(query_string, q.description, database.name, query_rows[0][0], q.Threshold,
                                  q.ExceptionSeverity,
                                  'moustafa.mamdouh@fawry.com , ' + q.recepients_alert, 'db')
                elif q.nature == 'decremental':
                    if int(q.Threshold) < result < int(q.WarningThreshold) :
                        send_mail(query_string, q.description, database.name, query_rows[0][0], q.Threshold,
                                  q.ExceptionSeverity,
                                  'moustafa.mamdouh@fawry.com , ' + q.recepients_warning, 'db')
                    elif result < int(q.Threshold):
                        send_mail(query_string, q.description, database.name, query_rows[0][0], q.Threshold,
                                  q.ExceptionSeverity,
                                  'moustafa.mamdouh@fawry.com , ' + q.recepients_alert, 'db')
    except Exception as e:
        print(str(e))
        traceback.print_exc()


def addQueriesMonitorRecord(query_rows, query, database, check_time):
    enable_monitoring = Configuration.objects.get(key='enable_monitoring').value
    if enable_monitoring == 'false':
        return
    result = query_rows[0][0]
    if database_used_type == 'sqlite':

        counterObject = QueriesMonitor(
            Query_id=query,
            database_id=database,
            count=result,
            CaptureTime=check_time,
            severity=q.ExceptionSeverity,
        )
        counterObject.save()

    elif database_used_type == 'mongodb':
        mongoDB.queries.insert_one({
            "name": query.name,
            "Query": query.query,
            "database": database.name,
            "count": result,
            "CaptureTime": check_time,
            "severity": query.ExceptionSeverity.Code
        })


def displayExceptionsGraphs(ip_list, trx_date):
    if database_used_type == 'sqlite':
        records = ExceptionsMonitor.objects.filter(server_id__IP__in=ip_list, lastAlertTime__contains=trx_date).order_by(
            'Exception_id', 'lastAlertTime', 'server_id')

        if len(records) < 1:
            return HttpResponse("no records found within this date")
        exceptions_ends = []
        for x in range(len(records)):
            if x == len(records) - 1:
                continue
            elif records[x].Exception_id == records[x + 1].Exception_id:
                continue
            exceptions_ends.append(x)

        y = 0
        exceptions_data = list()
        for x in exceptions_ends:
            exception_records = list()
            for z in range(y, x + 1):
                exception_records.append(records[z])
            exceptions_data.append(exception_records)
            y = x + 1

        exception_records = list()
        for z in range(exceptions_ends[-1] + 1, len(records)):
            exception_records.append(records[z])
        exceptions_data.append(exception_records)

        result = list()
        for exceptiongraph in exceptions_data:
            exception_ends = []
            for x in range(len(exceptiongraph)):
                if x == len(exceptiongraph) - 1:
                    continue
                elif exceptiongraph[x].lastAlertTime == exceptiongraph[x + 1].lastAlertTime:
                    continue
                exception_ends.append(x)
            y = 0
            exception_info = list()
            for x in exception_ends:
                exception_records = list()
                for z in range(y, x + 1):
                    exception_records.append(exceptiongraph[z])
                exception_info.append(exception_records)
                y = x + 1
            exception_records = list()
            for z in range(exception_ends[-1] + 1, len(exceptiongraph)):
                exception_records.append(exceptiongraph[z])
            exception_info.append(exception_records)

            exception_records = list()
            for element in exception_info:
                rec = list()
                for exp in element:
                    rec.append(exp.count)
                while len(rec) < len(ip_list):
                    rec.append(0)
                rec = [str(element[0].lastAlertTime)] + rec

                exception_records.append(rec)
            dict = {str(exception_info[0][0].Exception_id): exception_records}
            result.append(dict)

        return json.dumps(result)

    elif database_used_type == 'mongodb':
        curr_date = datetime.datetime.strptime(trx_date, "%Y-%m-%d")
        print(curr_date)
        no_of_days = datetime.timedelta(days=1)
        next_day = curr_date + no_of_days
        print(next_day)

        records = list(mongoDB.exceptions.find({
                            "server_id": {"$in": ip_list},
                            "lastAlertTime": {"$lt": next_day},
                            "lastAlertTime": {"$gt": curr_date},
                            "count": {"$gt": 0}
        }).sort([
                            ('Exception_id', pymongo.ASCENDING),
                            ('lastAlertTime', pymongo.ASCENDING),
                            ('server_id', pymongo.ASCENDING)]
        ))

        print(records)
        if len(records) < 1:
            return "no records found within this date"
        exceptions_ends = []
        for x in range(len(records)):
            try:
                if x + 1 == len(records):
                    exceptions_ends.append(x)
                    break
                elif records[x]['Exception_id'] == records[x + 1]['Exception_id']:
                    continue
                exceptions_ends.append(x)
            except IndexError:
                continue

        y = 0
        exceptions_data = list()
        for x in exceptions_ends:
            exception_records = list()
            for z in range(y, x + 1):
                exception_records.append(records[z])
            exceptions_data.append(exception_records)
            y = x + 1

        result = list()
        for exceptiongraph in exceptions_data:
            exception_ends = []
            for x in range(len(exceptiongraph)):
                if x + 1 == len(exceptiongraph):
                    exception_ends.append(x)
                    break
                elif exceptiongraph[x]['lastAlertTime'] == exceptiongraph[x + 1]['lastAlertTime']:
                    continue
                exception_ends.append(x)
            y = 0
            exception_info = list()
            for x in exception_ends:
                exception_records = list()
                for z in range(y, x + 1):
                    exception_records.append(exceptiongraph[z])
                exception_info.append(exception_records)
                y = x + 1

            exception_records = list()
            for element in exception_info:
                rec = form_grap_entry(element, ip_list, 'exceptions')
                rec = [str(element[0]['lastAlertTime'])] + rec
                exception_records.append(rec)

            dict = {str(exception_info[0][0]['Exception_id']): exception_records}
            result.append(dict)
        return json.dumps(result)


def displayQueriesGraphs(database, trx_date, severity):
    if database_used_type == 'sqlite':
        records = QueriesMonitor.objects.filter(database_id__id=database.id, CaptureTime__contains=trx_date,
                                                severity=severity).order_by('Query_id', 'CaptureTime')
        print(len(records))
        if len(records) < 1:
            return "no records found within this date"
        exceptions_ends = []

        for x in range(len(records)):
            if x == len(records) - 1:
                exceptions_ends.append(x)
                continue
            elif records[x].Query_id == records[x + 1].Query_id:
                continue
            exceptions_ends.append(x)

        y = 0
        exceptions_data = list()
        for x in exceptions_ends:
            exception_records = list()
            for z in range(y, x + 1):
                exception_records.append(records[z])
            exceptions_data.append(exception_records)
            y = x + 1

        exception_records = list()
        for z in range(exceptions_ends[-1] + 1, len(records)):
            exception_records.append(records[z])
        exceptions_data.append(exception_records)

        result = list()
        for exceptiongraph in exceptions_data:
            exception_ends = []
            for x in range(len(exceptiongraph)):
                if x == len(exceptiongraph) - 1:
                    continue
                elif exceptiongraph[x].CaptureTime == exceptiongraph[x + 1].CaptureTime:
                    continue
                exception_ends.append(x)
            y = 0
            exception_info = list()
            for x in exception_ends:
                exception_records = list()
                for z in range(y, x + 1):
                    exception_records.append(exceptiongraph[z])
                exception_info.append(exception_records)
                y = x + 1
            exception_records = list()
            if len(exception_ends) < 1:
                continue
            for z in range(exception_ends[-1] + 1, len(exceptiongraph)):
                exception_records.append(exceptiongraph[z])
            exception_info.append(exception_records)

            exception_records = list()
            for element in exception_info:
                rec = list()
                for exp in element:
                    rec.append(exp.count)
                rec = [str(element[0].CaptureTime)] + rec

                exception_records.append(rec)
            query_name = str(exception_info[0][0].Query_id.query).replace(
                'gateway_pmt_creation_date between \'{}\' and \'{}\' and', '').replace('\"', '')
            dict = {query_name: exception_records}
            result.append(dict)

        return(json.dumps(result))

    elif database_used_type == 'mongodb':

        curr_date = datetime.datetime.strptime(trx_date, "%Y-%m-%d")
        print(curr_date)
        no_of_days = datetime.timedelta(days=1)
        next_day = curr_date + no_of_days
        print(next_day)

        records = list(mongoDB.queries.find({
            "database": database.name,
            "CaptureTime": {"$lt": next_day},
            "CaptureTime": {"$gt": curr_date},
            "severity": severity
        }).sort([
            ('name', pymongo.ASCENDING),
            ('CaptureTime', pymongo.ASCENDING)
        ]))
        print(database.name, severity)
        print(records)
        if len(records) < 1:
            return "no records found within this date"
        exceptions_ends = []

        for x in range(len(records)):
            if x == len(records) - 1:
                exceptions_ends.append(x)
                continue
            elif records[x]['name'] == records[x + 1]['name']:
                continue
            exceptions_ends.append(x)

        y = 0
        exceptions_data = list()
        for x in exceptions_ends:
            exception_records = list()
            for z in range(y, x + 1):
                exception_records.append(records[z])
            exceptions_data.append(exception_records)
            y = x + 1

        exception_records = list()
        for z in range(exceptions_ends[-1] + 1, len(records)):
            exception_records.append(records[z])
        exceptions_data.append(exception_records)

        result = list()
        for exceptiongraph in exceptions_data:
            exception_ends = []
            for x in range(len(exceptiongraph)):
                if x == len(exceptiongraph) - 1:
                    continue
                elif exceptiongraph[x]['CaptureTime'] == exceptiongraph[x + 1]['CaptureTime']:
                    continue
                exception_ends.append(x)
            y = 0
            exception_info = list()
            for x in exception_ends:
                exception_records = list()
                for z in range(y, x + 1):
                    exception_records.append(exceptiongraph[z])
                exception_info.append(exception_records)
                y = x + 1
            exception_records = list()
            if len(exception_ends) < 1:
                continue
            for z in range(exception_ends[-1] + 1, len(exceptiongraph)):
                exception_records.append(exceptiongraph[z])
            exception_info.append(exception_records)

            exception_records = list()
            for element in exception_info:
                rec = list()
                for exp in element:
                    rec.append(exp['count'])
                rec = [str(element[0]['CaptureTime'])] + rec

                exception_records.append(rec)
            query_name = str(exception_info[0][0]['name'])
            dict = {query_name: exception_records}
            result.append(dict)

        print(json.dumps(result))
        return (json.dumps(result))


def getWebsphereQueueinfo(server, in_queue, timestamp):
    enable_monitoring = Configuration.objects.get(key='enable_monitoring').value
    if enable_monitoring == 'false':
        return

    result = getQueuesCounts(server)
    jsonObject = json.loads(result)

    if database_used_type == 'sqlite':
        return
    elif database_used_type == 'mongodb':
        for bus in jsonObject['SIBusSummary']['Bus']:
            messagingEngine = bus["MessagingEngine"]
            queuePoints = messagingEngine['QueuePoints']['QueuePoint']
            for queuePoint in queuePoints:
                mongoDB.queues.insert_one({
                    "server": server.IP,
                    "group": server.group_name.groupName,
                    "name": queuePoint['name'],
                    "state": queuePoint['state'],
                    "depth": int(queuePoint['depth']),
                    "highMessageThreshold": int(queuePoint['highMessageThreshold']),
                    "MessagingEngineName": messagingEngine["name"],
                    "MessagingEngineState": messagingEngine["state"],
                    "BusName": bus["name"],
                    "creation_date": timestamp
                })

        print(bus)
    in_queue.put(result)


def displayQueuesGraphs(ip_list, trx_date):
    if database_used_type == '':
        return "no results found, as current used DB is not supported"

    elif database_used_type == 'mongodb':
        curr_date = datetime.datetime.strptime(trx_date, "%Y-%m-%d")
        no_of_days = datetime.timedelta(days=1)
        next_day = curr_date + no_of_days

        records = list(mongoDB.queues.find({
            "server": {"$in": ip_list},
            "creation_date": {"$lt": next_day},
            "creation_date": {"$gt": curr_date},
            "depth": {"$gt": 0}
        }).sort([
            ('name', pymongo.ASCENDING),
            ('creation_date', pymongo.ASCENDING),
            ('server', pymongo.ASCENDING)]
        ))

        if len(records) < 1:
            return "no records found within this date"
        exceptions_ends = []
        for x in range(len(records)):
            try:
                if x + 1 == len(records):
                    exceptions_ends.append(x)
                    break
                elif records[x]['name'] == records[x + 1]['name']:
                    continue
                exceptions_ends.append(x)
            except IndexError:
                continue

        y = 0
        exceptions_data = list()
        for x in exceptions_ends:
            exception_records = list()
            for z in range(y, x + 1):
                exception_records.append(records[z])
            exceptions_data.append(exception_records)
            y = x + 1

        result = list()
        for exceptiongraph in exceptions_data:
            exception_ends = []
            for x in range(len(exceptiongraph)):
                if x + 1 == len(exceptiongraph):
                    exception_ends.append(x)
                    break
                elif exceptiongraph[x]['creation_date'] == exceptiongraph[x + 1]['creation_date']:
                    continue
                exception_ends.append(x)
            y = 0
            exception_info = list()
            for x in exception_ends:
                exception_records = list()
                for z in range(y, x + 1):
                    exception_records.append(exceptiongraph[z])
                exception_info.append(exception_records)
                y = x + 1

            exception_records = list()
            for element in exception_info:
                rec = form_grap_entry(element, ip_list, 'queues')
                rec = [str(element[0]['creation_date'])] + rec
                exception_records.append(rec)

            dict = {str(exception_info[0][0]['name']): exception_records}
            result.append(dict)
        return json.dumps(result)


def form_grap_entry(element_group, full_pattern, type):
    result_list = [-1] * len(full_pattern)
    for x in range(len(full_pattern)):
        for element in element_group:
            if type == 'exceptions':
                if full_pattern[x] == element['server_id']:
                    result_list[x] = element['count']
            elif type == 'queues':
                if full_pattern[x] == element['server']:
                    result_list[x] = element['depth']
    for y in range(len(result_list)):
        if result_list[y] == -1:
            result_list[y] = 0
    return result_list