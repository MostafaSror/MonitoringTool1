import paramiko

# if len(sys.argv) < 4:
#    print("args missing")
#    sys.exit(1)


env = ["10.100.4.64", "10.100.4.65"]
username = "mmamdouh"
password = "December2019#"

for hostname in env:
#hostname = "10.100.4.65"
#    password = "P@ssw0rd"
    command = "cd /waslogs/logs/traces ; grep -l '942b0366-887c-42cb-be1d-b65cfdc88292' trace*"
    command1 = "pwd"
    #    username = "wasadmin"
    port = 22
    try:
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname, port, username, password)
        client.exec_command(command)
        print(hostname)
        print("=================")
        stdin, stdout, stderr = client.exec_command(command)
        print(stdout.read())
        print('\n')

    finally:
        client.close()
