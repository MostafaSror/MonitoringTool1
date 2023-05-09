from .models import Configuration

from pymongo import MongoClient
import cx_Oracle

from ldap3 import Server as LdapServer, Connection as LDAPConnection, ALL, SUBTREE
from ldap3.core.exceptions import LDAPException, LDAPBindError

import smtplib
from string import Template
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import traceback

import paramiko
import subprocess

environment_nature = Configuration.objects.get(key='env_nature').value
remote_win_out_path = Configuration.objects.get(key='remote_win_out_path', env=environment_nature).value
remote_win_out_name = Configuration.objects.get(key='remote_win_out_name', env=environment_nature).value
local_win_out_path = Configuration.objects.get(key='local_win_out_path', env=environment_nature).value
local_win_out_name = Configuration.objects.get(key='local_win_out_name', env=environment_nature).value
remote_aix_deployment_folder = Configuration.objects.get(key='remote_aix_deployment_folder', env=environment_nature).value
remote_win_deployment_folder = Configuration.objects.get(key='remote_win_deployment_folder', env=environment_nature).value
batch_files_path = Configuration.objects.get(key='batch_files_path', env=environment_nature).value
local_win_deployment_folder = Configuration.objects.get(key='local_win_deployment_folder', env=environment_nature).value


def MongoConnection(conn_string):
    client = MongoClient(conn_string)
    db = client.MonitoringTool
    return db


def OracleConnection(ip, port, service_name, user, password):
    try:
        dsn_tns = cx_Oracle.makedsn(ip, port, service_name=service_name)
        conn = cx_Oracle.connect(user=user, password=password, dsn=dsn_tns)
        return conn
    except cx_Oracle.Error as error:
        print("Issue while connecting to " + str(ip) + " : " + str(error))
        traceback.print_exc()
        return "failure while connecting to DB: " + ip
    except Exception as e:
        print("Issue while connecting to " + str(ip) + " : " + str(e))
        traceback.print_exc()
        return "failure while connecting to DB: " + ip


def LdapConnection(user):
    if user.has_perm('auth.search_myfawry_users'):
        try:

            # Provide the hostname and port number of the openLDAP
            server_uri = f"ldap://10.100.81.43:1389"
            server = LdapServer(server_uri, get_info=ALL)
            # username and password can be configured during openldap setup
            connection = LDAPConnection(server,
                                user='cn=root',
                                password='P@ssw0rd@123')
            bind_response = connection.bind()  # Returns True or False

            return connection
        except LDAPBindError as e:
            print(e.with_traceback())
        except ldap3.core.exceptions.LDAPSessionTerminatedByServerError as e:
            return "LDAP connectoin terminated, please try search again"
    else:
        return "user has no permission to use this function"


def send_mail(excep, desc, group, curr_count, max, sev, recepients, type, ipaddress='', is_testing=True):
    # set up the SMTP server
    if not is_testing:
        s = smtplib.SMTP(host='10.100.36.40', port='25')
    # s.starttls()
    # s.login(MY_ADDRESS, PASSWORD)

    # For each contact, send the email:
    # for name, email in zip(names, emails):
    msg = MIMEMultipart()  # create a message

    # names, emails = get_contacts('mycontacts.txt') # read contacts
    if type == 'app':
        message_template = read_template('template.html')
        msg['From'] = 'support-app@fawry.com'
        message = message_template.substitute(ex_name=excep, group_name=group, ip_address=ipaddress, curr_count=curr_count, max_count=max,
                                              severity=sev)
    elif type == 'db':
        message_template = read_template('db-template.html')
        msg['From'] = 'support-db@fawry.com'
        message = message_template.substitute(ex_name=excep, group_name=group, curr_count=curr_count, max_count=max,
                                              severity=sev, description=desc)
    elif type == 'api':
        message_template = read_template('db-template.html')
        msg['From'] = 'support-api@fawry.com'
        message = message_template.substitute(ex_name=excep, group_name=group, curr_count=curr_count, max_count=max,
                                              severity=sev, description=desc)
    elif type == 'ach':
        message_template = read_template('ach-template.html')
        msg['From'] = 'support-ach@fawry.com'
        message = message_template.substitute(file_name=excep, size=desc)

    # add in the actual person name to the message template

    #message = 'test'
    # Prints out the message body for our sake
    print(message)

    msg['To'] = recepients
    msg['Subject'] = "This is Monitoring Tool notification"

    # add in the message body
    msg.attach(MIMEText(message, 'html'))

    # send the message via the server set up earlier.
    is_testing = True
    if not is_testing:
        s.send_message(msg)

        del msg
        # Terminate the SMTP session and close the connection
        s.quit()


class ServerConnection:
    def __init__(self, machine):
        self.machine = machine

    def connect_ssh(self):
        if self.machine.os == 'aix':
            self.client = paramiko.SSHClient()
            self.client.load_system_host_keys()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(self.machine.IP, 22, self.machine.app_user, self.machine.app_password)
        if self.machine.os == 'linux':
            self.client = paramiko.SSHClient()
            self.client.load_system_host_keys()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(self.machine.IP, 22, self.machine.app_user, self.machine.app_password)
        elif self.machine.os == 'windows':
            pythoncom.CoInitialize()
            self.client = wmi.WMI(self.machine.IP, user=self.machine.app_user, password=self.machine.app_password)

    def disconnect_ssh(self):
        if self.machine.os in ('aix', 'linux'):
            self.client.close()
        elif self.machine.os == 'windows':
            pythoncom.CoUninitialize()

    def exec_command(self, command, skip_print_log=None):
        print(command)
        if self.machine.os in ('aix', 'linux'):
            stdin, stdout, stderr = self.client.exec_command(command)
            temp = stdout.read()
            if skip_print_log is None:
                print(temp.decode("utf-8"))

            """while not self.client.recv_exit_status():
                if self.client.recv_ready():
                    data = self.client.recv(1024)
                    while data:
                        print data
                        data = chan.recv(1024)

                if self.client.recv_stderr_ready():
                    error_buff = self.client.recv_stderr(1024)
                    while error_buff:
                        print error_buff
                        error_buff = self.client.recv_stderr(1024)
                exist_status = self.client.recv_exit_status()
                if 0 == exist_status:"""
            return temp.decode("utf-8")

        elif self.machine.os == 'windows':
            """
            tool = WinOSClient(self.machine.IP, self.machine.app_user, self.machine.app_password, logger_enabled=False)
            response = tool.run_cmd(command='ipconfig > c:\\deployment\\dir.log')
            print(response.ok)
            """
            psexec_path = local_win_deployment_folder + r'\PSTools\psexec.exe'
            cmd = r' \\' + self.machine.IP + r'\deployment\new.bat "' + command + '" ' + remote_win_out_path + '\\' + remote_win_out_name
            print(psexec_path + cmd)
            process = subprocess.Popen(psexec_path + cmd, shell=True, stdout=subprocess.PIPE)
            (outs, errs) = process.communicate(input=None, timeout=None)
            print(outs)

            """
            exec_cmd = r'cmd.exe /c ' + remote_win_out_path + '\\New.bat ' + command + ' ' + remote_win_out_path + '\\' + remote_win_out_name + ''
            print(exec_cmd)
            process_id, result = self.client.Win32_Process.Create(CommandLine=exec_cmd)

            watcher = self.client.watch_for(
                notification_type="Deletion",
                wmi_class="Win32_Process",
                delay_secs=1,
                ProcessId=process_id
            )
            watcher()
            """
            # print(result)
            """
            conn = SMBConnection(self.machine.app_user, self.machine.app_password, 'test', self.machine.hostname, use_ntlm_v2=True)
            conn.connect(self.machine.IP, 139)
            with open(local_win_out_name, 'wb+') as fp:
                conn.retrieveFile('deployment', '/' + remote_win_out_name, fp)
            """
            cmnd = 'copy ' + '"\\\\' + self.machine.IP + '\\deployment\\' + remote_win_out_name + '" "' + local_win_out_path + '"'
            print(cmnd)
            stream = os.popen(cmnd)
            output = stream.read()
            print(output)
            with open(local_win_out_path + '\\' + local_win_out_name, 'r') as fr:
                lines = fr.readlines()
                output = ''
                for line in lines:
                    output += line
                print(output)
            # conn.close()
            return output

    def move_remotely_to_win(self, folder_name):
        if self.machine.os in ('aix', 'linux'):
            try:
                process = subprocess.Popen([folder_name, self.machine.IP, username_property, password_property],
                                           shell=True, stdout=subprocess.PIPE)
                (outs, errs) = process.communicate(input=None, timeout=None)
                print(outs)
                return outs
            except TimeoutError as e:
                print(str(e))
                process.kill()
                print(process.pid + " on server: " + self.machine.IP + " is killed.")
                return b''
            except Exception as e:
                print(str(e))
                return str(e)
            finally:
                process.terminate()

        elif self.machine.os == 'windows':
            try:
                conn = SMBConnection(self.machine.app_user, self.machine.app_password, 'test', self.machine.hostname,
                                     use_ntlm_v2=True)
                conn.connect(self.machine.IP, 139)
                files = conn.listPath('deployment', folder_name, search=65591, pattern='*', timeout=30)
                if len(files) > 2:
                    for x in range(2, len(files) - 1):
                        print(str(files[x].filename))
                    conn.deleteFiles('deployment', '/' + folder_name + '/*', delete_matching_folders=True, timeout=30)
            except smb_structs.OperationFailure as e:
                print(str(e))
                conn.createDirectory('deployment', folder_name)
            finally:
                path = local_win_deployment_folder + '\\' + folder_name
                copy_files_remotely(path, folder_name, self.machine.IP, conn)
                conn.close()
            return 'moving resources'.encode("utf-8")


def move_to_remote(host, type):
    print("In move_to_remote")

    if type == 'scripts':
        try:
            srv_conn = ServerConnection(host)
            srv_conn.connect_ssh()

            if host.os in ('aix', 'linux'):
                command = 'if [ -d "' + remote_aix_deployment_folder + '/scripts" ]; then echo "scripts exists"; else mkdir -p ' + \
                          remote_aix_deployment_folder + '/scripts && chmod 777 ' + remote_aix_deployment_folder + '/scripts;  fi'
                srv_conn.exec_command(command)
                filepath = batch_files_path + r'\transfer_remote.bat'
                return srv_conn.move_remotely_to_win(filepath)

            elif host.os == 'windows':
                command = '"if exist "' + remote_win_deployment_folder + '\scripts" (echo ""scripts exist"") else (mkdir ' + \
                          remote_win_deployment_folder + '\scripts)"'
                srv_conn.exec_command(command)
                return srv_conn.move_remotely_to_win('scripts')

        except paramiko.ssh_exception.AuthenticationException:
            err = 'Invalid username or password for machine : ' + host.IP
            return err.encode("utf-8")
        except Exception as e:
            print(str(e))
            return b''
        finally:
            srv_conn.disconnect_ssh()

    elif type == 'ear' or type == 'sw_ear':
        try:
            srv_conn = ServerConnection(host)
            srv_conn.connect_ssh()

            if host.os in ('aix', 'linux'):
                command = 'if [ -d "' + remote_aix_deployment_folder + '/ear" ]; then echo "old ear exists" && rm -r ' + \
                          remote_aix_deployment_folder + '/ear/* ; else mkdir -p ' + \
                          remote_aix_deployment_folder + '/ear && chmod 777 ' + remote_aix_deployment_folder + '/ear;  fi'
                srv_conn.exec_command(command)
                if type == 'ear':
                    filepath = batch_files_path + r'\transfer_ear_remote.bat'
                elif type == 'sw_ear':
                    filepath = batch_files_path + r'\transfer_sw_ear_remote.bat'
                return srv_conn.move_remotely_to_win(filepath)
            elif host.os == 'windows':
                command = '"if exist "' + remote_win_deployment_folder + r'\ear" (echo ""old ear exists"" && del /q ' + \
                          remote_win_deployment_folder + r'\ear) else (mkdir ' + \
                          remote_win_deployment_folder + r'\ear)"'
                srv_conn.exec_command(command)
                return srv_conn.move_remotely_to_win('ear')

        except paramiko.ssh_exception.AuthenticationException:
            err = 'Invalid username or password for machine : ' + host.IP
            return err.encode("utf-8")
        except Exception as e:
            print(str(e))
            return b''
        finally:
            srv_conn.disconnect_ssh()

    elif type == 'resources':
        try:
            srv_conn = ServerConnection(host)
            srv_conn.connect_ssh()

            if host.os in ('aix', 'linux'):
                command = 'if [ -d "' + remote_aix_deployment_folder + '/resources" ]; then echo "resources exists" && rm -r ' + \
                          remote_aix_deployment_folder + '/resources/* ; else mkdir -p ' + \
                          remote_aix_deployment_folder + '/resources && chmod 777 ' + remote_aix_deployment_folder + '/resources;  fi'
                srv_conn.exec_command(command)

                command = 'if [ -d "' + remote_aix_deployment_folder + '/backup" ]; then echo "resources exists" ; else mkdir -p ' + \
                          remote_aix_deployment_folder + '/backup && chmod 777 ' + remote_aix_deployment_folder + '/backup;  fi'
                srv_conn.exec_command(command)

                filepath = batch_files_path + r'\transfer_resources_remote.bat'
                out = srv_conn.move_remotely_to_win(filepath)

                client = paramiko.SSHClient()
                client.load_system_host_keys()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(host.IP, 22, username_property, password_property)
                command = 'chmod -R 777 /waslogs/deployment/resources/*'
                stdin, stdout, stderr = client.exec_command(command)
                temp = stdout.read()
                if temp != None:
                    print('%%Changing mode of resources files%%')
                    #print(temp.decode("utf-8"))
                client.close()
                return out
            elif host.os == 'windows':
                command = '"if exist "' + remote_win_deployment_folder + r'\resources" (echo ""resources exists"" && del /q ' + \
                          remote_win_deployment_folder + r'\resources && FOR /D %p IN ("' + remote_win_deployment_folder +\
                          r'\resources\*.*") DO rmdir "%p") else (mkdir ' + \
                          remote_win_deployment_folder + r'\resources)"'
                srv_conn.exec_command(command)
                return srv_conn.move_remotely_to_win('resources')

        except paramiko.ssh_exception.AuthenticationException:
            err = 'Invalid username or password for machine : ' + host.IP
            return err.encode("utf-8")
        except Exception as e:
            print(str(e))
            return b''
        finally:
            srv_conn.disconnect_ssh()

    elif type == 'lib':
        try:
            srv_conn = ServerConnection(host)
            srv_conn.connect_ssh()

            if host.os in ('aix', 'linux'):
                command = 'if [ -d "' + remote_aix_deployment_folder + '/lib" ]; then echo "lib exists" && rm -r ' + \
                          remote_aix_deployment_folder + '/lib/* ; else mkdir -p ' + \
                          remote_aix_deployment_folder + '/lib && chmod 777 ' + remote_aix_deployment_folder + '/lib;  fi'
                srv_conn.exec_command(command)

                filepath = batch_files_path + r'\transfer_lib_remote.bat'
                out = srv_conn.move_remotely_to_win(filepath)

                client = paramiko.SSHClient()
                client.load_system_host_keys()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(host.IP, 22, username_property, password_property)
                command = 'chmod -R 777 /waslogs/deployment/lib/*'
                stdin, stdout, stderr = client.exec_command(command)
                temp = stdout.read()
                if temp != None:
                    print('%%Changing mode of resources files%%')
                    #print(temp.decode("utf-8"))
                client.close()
                return out
            elif host.os == 'windows':
                command = '"if exist "' + remote_win_deployment_folder + r'\lib" (echo ""lib exists"" && del /q ' + \
                          remote_win_deployment_folder + r'\lib && FOR /D %p IN ("' + remote_win_deployment_folder +\
                          r'\lib\*.*") DO rmdir "%p") else (mkdir ' + \
                          remote_win_deployment_folder + r'\lib)"'
                srv_conn.exec_command(command)
                return srv_conn.move_remotely_to_win('lib')

        except paramiko.ssh_exception.AuthenticationException:
            err = 'Invalid username or password for machine : ' + host.IP
            return err.encode("utf-8")
        except Exception as e:
            print(str(e))
            return b''
        finally:
            srv_conn.disconnect_ssh()

    elif type == 'queues':
        try:
            srv_conn = ServerConnection(host)
            srv_conn.connect_ssh()
            if host.os in ('aix', 'linux'):
                command = 'if [ -d "' + remote_aix_deployment_folder + '/queues" ]; then echo "queues exists" && rm -r ' + \
                          remote_aix_deployment_folder + '/queues/* ; else mkdir -p ' + \
                          remote_aix_deployment_folder + '/queues && chmod 777 ' + remote_aix_deployment_folder + '/queues;  fi'
                srv_conn.exec_command(command)
                filepath = batch_files_path + r'\transfer_queues_remote.bat'
                return srv_conn.move_remotely_to_win(filepath)
            elif host.os == 'windows':
                command = '"if exist "' + remote_win_deployment_folder + r'\queues" (echo ""queues exists"" && del /q ' + \
                          remote_win_deployment_folder + r'\queues && FOR /D %p IN ("' + remote_win_deployment_folder +\
                          r'\queues\*.*") DO rmdir "%p") else (mkdir ' + \
                          remote_win_deployment_folder + r'\queues)"'
                srv_conn.exec_command(command)
                return srv_conn.move_remotely_to_win('queues')

        except paramiko.ssh_exception.AuthenticationException:
            err = 'Invalid username or password for machine : ' + host.IP
            return err.encode("utf-8")
        except Exception as e:
            print(str(e))
            return b''
        finally:
            srv_conn.disconnect_ssh()

    else:
        print("incorrect type defined in move to remote fn")
        return b'nothing moved. Please check the type in move to remote'