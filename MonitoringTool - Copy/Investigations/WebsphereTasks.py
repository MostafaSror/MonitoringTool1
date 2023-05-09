from .InfraUtilities import ServerConnection, move_to_remote
from.models import Configuration

import xmltodict, json

environment_nature = Configuration.objects.get(key='env_nature').value
remote_aix_deployment_folder = Configuration.objects.get(key='remote_aix_deployment_folder', env=environment_nature).value
remote_win_deployment_folder = Configuration.objects.get(key='remote_win_deployment_folder', env=environment_nature).value


def getQueuesCounts(srv):
    serverConn = ServerConnection(srv)

    move_to_remote(srv, 'scripts')

    serverConn.connect_ssh()
    if srv.os in ('aix', 'linux'):
        command = "cd " + srv.bin_path + " ; ./wsadmin.sh -lang jython -conntype SOAP -port " \
                  + srv.soap_port + " -username " + srv.app_user + " -password " + srv.soap_pass \
                  + " -f " + remote_aix_deployment_folder + "/scripts/printSIBusSummary.py "
    elif srv.os == 'windows':
        command = '"' + srv.bin_path + '\wsadmin^ -lang jython -conntype SOAP -port ' \
                  + srv.soap_port + " -username " + srv.app_user + " -password " + srv.soap_pass \
                  + " -f " + remote_win_deployment_folder + "\scripts\printSIBusSummary.py "

    output = serverConn.exec_command(command, True)
    output = xmltodict.parse('\n'.join(output.split('\n')[1:]), attr_prefix='')
    data_dict = json.dumps(output)
    serverConn.disconnect_ssh()
    return data_dict

