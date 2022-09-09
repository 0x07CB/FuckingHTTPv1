#from tkinter import E
from sh import sh
#from sh import ErrorReturnCode
from sh import Command as Cmd
#from sh import ifconfig
#from sh import hping3
import keyboard
from multiprocessing import Process
import socket #,requests
import subprocess
command_=""

VERBOSE = True
ENABLE_UFW_RULES_SETTERS = True

# function to print _command information of execution if the VERBOSE setting is True
def verbose_printing_system_command_information_of_execution(_command):
    # show command in console only if VERBOSE is True
    if VERBOSE:
        # display the command to be executed in blue color with the green prefix string '[+] EXECUTION OF THE SYSTEM COMMAND: ' 
        print(command_)
        
# function to print _command_output information of execution if the VERBOSE setting is True
def verbose_printing_system_command_output_information_of_execution(_command_output):
    # show command in console only if VERBOSE is True
    if VERBOSE:
        # display the command to be executed in blue color with the green prefix string '[+] EXECUTION OF THE SYSTEM COMMAND: ' 
        print(_command_output)

class UFW_RulesSetters(object):
    def __init__(self):
        self.UFW_FIREWALL_RULES_TO_SET = []
    # function to default deny all incoming traffic to the specified port
    def default_deny_all_incoming_traffic_to_port(self,port=80,EXIT_ON_FAILURE=True):
        try:
            command_="sudo ufw default deny incoming to any port "+str(port)
            verbose_printing_system_command_information_of_execution(command_)
            process = subprocess.Popen(command_, stdout=subprocess.PIPE, shell=True)
            (output, err) = process.communicate()
            process_status = process.wait()
            verbose_printing_system_command_output_information_of_execution(output)
            if VERBOSE:
                print("Command exit status/return code : ", process_status)
        except:
            print("Error in ufw usage from inside of default_deny_all_incoming_traffic_to_port function !")
            if EXIT_ON_FAILURE == True:
                exit(1)
    # function to allow all outgoing traffic to the specified ip destination
    def default_allow_all_outgoing_traffic_to_ip(self,ip_destination,port=80,EXIT_ON_FAILURE=True):
        try:
            command_="sudo ufw allow outgoing to "+ip_destination+" port "+str(port)
            verbose_printing_system_command_information_of_execution(command_)
            process = subprocess.Popen(command_, stdout=subprocess.PIPE, shell=True)
            (output, err) = process.communicate()
            process_status = process.wait()
            verbose_printing_system_command_output_information_of_execution(output)
            if VERBOSE:
                print("Command exit status/return code : ", process_status)
        except:
            print("Error in ufw usage from inside of default_allow_all_outgoing_traffic_to_ip function !")
            if EXIT_ON_FAILURE == True:
                exit(1)
    # function to use ufw with subprocess function (with return of output) to allow an precise IP to access in inbound connection to the http server in this machine with an default port of 80
    def allow_ip(self,ip_allowed_inbound_client,port=80,EXIT_ON_FAILURE=True):
        try:
            command_="sudo ufw allow from "+ip_allowed_inbound_client+" to any port "+str(port)
            verbose_printing_system_command_information_of_execution(command_)
            process = subprocess.Popen(command_, stdout=subprocess.PIPE, shell=True)
            (output, err) = process.communicate()
            process_status = process.wait()
            verbose_printing_system_command_output_information_of_execution(output)
            if VERBOSE:
                print("Command exit status/return code : ", process_status)
        except:
            print("Error in ufw usage from inside of allow_ip function !")
            if EXIT_ON_FAILURE == True:
                exit(1)
    # and same thing to deny an IP
    def deny_ip(self,ip_denied_inbound_client,port=80,EXIT_ON_FAILURE=True):
        try:
            command_="sudo ufw deny from "+ip_denied_inbound_client+" to any port "+str(port)
            verbose_printing_system_command_information_of_execution(command_)
            process = subprocess.Popen(command_, stdout=subprocess.PIPE, shell=True)
            (output, err) = process.communicate()
            process_status = process.wait()
            verbose_printing_system_command_output_information_of_execution(output)
            if VERBOSE:
                print("Command exit status/return code : ", process_status)
        except:
            print("Error in ufw usage from inside of deny_ip function !")
            if EXIT_ON_FAILURE == True:
                exit(1)
    # and same things to LIMIT an IP
    def limit_ip(self,ip_denied_inbound_client,port=80,EXIT_ON_FAILURE=True):
        try:
            command_="sudo ufw limit from "+ip_denied_inbound_client+" to any port "+str(port)
            verbose_printing_system_command_information_of_execution(command_)
            process = subprocess.Popen(command_, stdout=subprocess.PIPE, shell=True)
            (output, err) = process.communicate()
            process_status = process.wait()
            verbose_printing_system_command_output_information_of_execution(output)
            if VERBOSE:
                print("Command exit status/return code : ", process_status)
        except:
            print("Error in ufw usage from inside of limit_ip function !")
            if EXIT_ON_FAILURE == True:
                exit(1)
    # and same things to REJECT an IP
    def reject_ip(self,ip_denied_inbound_client,port=80,EXIT_ON_FAILURE=True):
        try:
            command_="sudo ufw reject from "+ip_denied_inbound_client+" to any port "+str(port)
            verbose_printing_system_command_information_of_execution(command_)
            process = subprocess.Popen(command_, stdout=subprocess.PIPE, shell=True)
            (output, err) = process.communicate()
            process_status = process.wait()
            verbose_printing_system_command_output_information_of_execution(output)
            if VERBOSE:
                print("Command exit status/return code : ", process_status)
        except:
            print("Error in ufw usage from inside of reject_ip function !")
            if EXIT_ON_FAILURE == True:
                exit(1)
    # and same things to delete an allow rule from an IP
    def delete_allow_ip(self,ip_denied_inbound_client,port=80,EXIT_ON_FAILURE=True):
        try:
            command_="sudo ufw delete allow from "+ip_denied_inbound_client+" to any port "+str(port)
            verbose_printing_system_command_information_of_execution(command_)
            process = subprocess.Popen(command_, stdout=subprocess.PIPE, shell=True)
            (output, err) = process.communicate()
            process_status = process.wait()
            verbose_printing_system_command_output_information_of_execution(output)
            if VERBOSE:
                print("Command exit status/return code : ", process_status)
        except:
            print("Error in ufw usage from inside of delete_allow_ip function !")
            if EXIT_ON_FAILURE == True:
                exit(1)
    # and same things to delete an deny rule from an IP
    def delete_deny_ip(self,ip_denied_inbound_client,port=80,EXIT_ON_FAILURE=True):
        try:
            command_="sudo ufw delete deny from "+ip_denied_inbound_client+" to any port "+str(port)
            verbose_printing_system_command_information_of_execution(command_)
            process = subprocess.Popen(command_, stdout=subprocess.PIPE, shell=True)
            (output, err) = process.communicate()
            process_status = process.wait()
            verbose_printing_system_command_output_information_of_execution(output)
            if VERBOSE:
                print("Command exit status/return code : ", process_status)
        except:
            print("Error in ufw usage from inside of delete_deny_ip function !")
            if EXIT_ON_FAILURE == True:
                exit(1)
    # and same things to delete an limit rule from an IP
    def delete_limit_ip(self,ip_denied_inbound_client,port=80,EXIT_ON_FAILURE=True):
        try:
            command_="sudo ufw delete limit from "+ip_denied_inbound_client+" to any port "+str(port)
            verbose_printing_system_command_information_of_execution(command_)
            process = subprocess.Popen(command_, stdout=subprocess.PIPE, shell=True)
            (output, err) = process.communicate()
            process_status = process.wait()
            verbose_printing_system_command_output_information_of_execution(output)
            if VERBOSE:
                print("Command exit status/return code : ", process_status)
        except:
            print("Error in ufw usage from inside of delete_limit_ip function !")
            if EXIT_ON_FAILURE == True:
                exit(1)
    # and same things to delete an reject rule from an IP
    def delete_reject_ip(self,ip_denied_inbound_client,port=80,EXIT_ON_FAILURE=True):
        try:
            command_="sudo ufw delete reject from "+ip_denied_inbound_client+" to any port "+str(port)
            verbose_printing_system_command_information_of_execution(command_)
            process = subprocess.Popen(command_, stdout=subprocess.PIPE, shell=True)
            (output, err) = process.communicate()
            process_status = process.wait()
            verbose_printing_system_command_output_information_of_execution(output)
            if VERBOSE:
                print("Command exit status/return code : ", process_status)
        except:
            print("Error in ufw usage from inside of delete_reject_ip function !")
            if EXIT_ON_FAILURE == True:
                exit(1)
    def reload_ufw(self,EXIT_ON_FAILURE=True):
        try:
            command_="sudo ufw reload"
            verbose_printing_system_command_information_of_execution(command_)
            process = subprocess.Popen(command_, stdout=subprocess.PIPE, shell=True)
            (output, err) = process.communicate()
            process_status = process.wait()
            verbose_printing_system_command_output_information_of_execution(output)
            if VERBOSE:
                print("Command exit status/return code : ", process_status)
        except:
            print("Error in ufw usage from inside of reload_ufw function !")
            if EXIT_ON_FAILURE == True:
                exit(1)
    def systemd_installation_of_ufw_service(self,EXIT_ON_FAILURE=True):
        try:
            command_="sudo systemctl enable ufw"
            verbose_printing_system_command_information_of_execution(command_)
            process = subprocess.Popen(command_, stdout=subprocess.PIPE, shell=True)
            (output, err) = process.communicate()
            process_status = process.wait()
            verbose_printing_system_command_output_information_of_execution(output)
            if VERBOSE:
                print("Command exit status/return code : ", process_status)
        except:
            print("Error in ufw usage from inside of systemd_installation_of_ufw_service function !")
            if EXIT_ON_FAILURE == True:
                exit(1)
    def systemd_start_of_ufw_service(self,EXIT_ON_FAILURE=True):
        try:
            command_="sudo systemctl start ufw"
            verbose_printing_system_command_information_of_execution(command_)
            process = subprocess.Popen(command_, stdout=subprocess.PIPE, shell=True)
            (output, err) = process.communicate()
            process_status = process.wait()
            verbose_printing_system_command_output_information_of_execution(output)
            if VERBOSE:
                print("Command exit status/return code : ", process_status)
        except:
            print("Error in ufw usage from inside of systemd_start_of_ufw_service function !")
            if EXIT_ON_FAILURE == True:
                exit(1)
    def systemd_stop_of_ufw_service(self,EXIT_ON_FAILURE=True):
        try:
            command_="sudo systemctl stop ufw"
            verbose_printing_system_command_information_of_execution(command_)
            process = subprocess.Popen(command_, stdout=subprocess.PIPE, shell=True)
            (output, err) = process.communicate()
            process_status = process.wait()
            verbose_printing_system_command_output_information_of_execution(output)
            if VERBOSE:
                print("Command exit status/return code : ", process_status)
        except:
            print("Error in ufw usage from inside of systemd_stop_of_ufw_service function !")
            if EXIT_ON_FAILURE == True:
                exit(1)
    def systemd_restart_of_ufw_service(self,EXIT_ON_FAILURE=True):
        try:
            command_="sudo systemctl restart ufw"
            verbose_printing_system_command_information_of_execution(command_)
            process = subprocess.Popen(command_, stdout=subprocess.PIPE, shell=True)
            (output, err) = process.communicate()
            process_status = process.wait()
            verbose_printing_system_command_output_information_of_execution(output)
            if VERBOSE:
                print("Command exit status/return code : ", process_status)
        except:
            print("Error in ufw usage from inside of systemd_restart_of_ufw_service function !")
            if EXIT_ON_FAILURE == True:
                exit(1)
    def systemd_status_of_ufw_service(self,EXIT_ON_FAILURE=True):
        try:
            command_="sudo systemctl status ufw"
            verbose_printing_system_command_information_of_execution(command_)
            process = subprocess.Popen(command_, stdout=subprocess.PIPE, shell=True)
            (output, err) = process.communicate()
            process_status = process.wait()
            verbose_printing_system_command_output_information_of_execution(output)
            if VERBOSE:
                print("Command exit status/return code : ", process_status)
        except:
            print("Error in ufw usage from inside of systemd_status_of_ufw_service function !")
            if EXIT_ON_FAILURE == True:
                exit(1)
    def systemd_disable_of_ufw_service(self,EXIT_ON_FAILURE=True):
        try:
            command_="sudo systemctl disable ufw"
            verbose_printing_system_command_information_of_execution(command_)
            process = subprocess.Popen(command_, stdout=subprocess.PIPE, shell=True)
            (output, err) = process.communicate()
            process_status = process.wait()
            verbose_printing_system_command_output_information_of_execution(output)
            if VERBOSE:
                print("Command exit status/return code : ", process_status)
        except:
            print("Error in ufw usage from inside of systemd_disable_of_ufw_service function !")
            if EXIT_ON_FAILURE == True:
                exit(1)
    def ufw_status(self,ufwstatus_verbose_mode=True, EXIT_ON_FAILURE=True):
        try:
            command_="sudo ufw status"
            verbose_printing_system_command_information_of_execution(command_)
            process = subprocess.Popen(command_, stdout=subprocess.PIPE, shell=True)
            (output, err) = process.communicate()
            process_status = process.wait()
            if ufwstatus_verbose_mode == True:
                verbose_printing_system_command_output_information_of_execution(output)
            if VERBOSE:
                print("Command exit status/return code : ", process_status)
            return output
        except:
            print("Error in ufw usage from inside of ufw_status function !")
            if EXIT_ON_FAILURE == True:
                exit(1)
    def ufw_enable_command(self,EXIT_ON_FAILURE=True):
        try:
            command_="sudo ufw enable"
            verbose_printing_system_command_information_of_execution(command_)
            process = subprocess.Popen(command_, stdout=subprocess.PIPE, shell=True)
            (output, err) = process.communicate()
            process_status = process.wait()
            verbose_printing_system_command_output_information_of_execution(output)
            if VERBOSE:
                print("Command exit status/return code : ", process_status)
        except:
            print("Error in ufw usage from inside of ufw_enable_command function !")
            if EXIT_ON_FAILURE == True:
                exit(1)
    def ufw_disable_command(self, EXIT_ON_FAILURE=True):
        try:
            command_="sudo ufw disable"
            verbose_printing_system_command_information_of_execution(command_)
            process = subprocess.Popen(command_, stdout=subprocess.PIPE, shell=True)
            (output, err) = process.communicate()
            process_status = process.wait()
            verbose_printing_system_command_output_information_of_execution(output)
            if VERBOSE:
                print("Command exit status/return code : ", process_status)
        except:
            print("Error in ufw usage from inside of ufw_disable_command function !")
            if EXIT_ON_FAILURE == True:
                exit(1)
    def set_ufw_rules(self,LIST_OF_IP_UFW_RULES):
        self.UFW_FIREWALL_RULES_TO_SET=LIST_OF_IP_UFW_RULES
        return self
    def execute_rules_setting_up(self):
        for rule in self.UFW_FIREWALL_RULES_TO_SET:
            ip, port, action, delete_rule_at_end, comment = rule["ip"], rule["port"], rule["action"], rule["delete_rule_at_end"], rule["comment"]
            if action == "allow":
                self.allow_ip(ip, port)
            elif action == "deny":
                self.deny_ip(ip, port)
            elif action == "reject":
                self.reject_ip(ip, port)
            elif action=="limit":
                self.limit_ip(ip, port)
            else:
                print("Error in action type !")
                exit(1)
        return self
    def execute_deleting_rules(self):
        for rule in self.UFW_FIREWALL_RULES_TO_SET:
            ip, port, action, delete_rule_at_end, comment = rule["ip"], rule["port"], rule["action"], rule["delete_rule_at_end"], rule["comment"]
            if delete_rule_at_end == True:
                if action == "allow":
                    self.delete_allow_ip(ip, port)
                elif action == "deny":
                    self.delete_deny_ip(ip, port)
                elif action == "reject":
                    self.delete_reject_ip(ip, port)
                elif action == "limit":
                    self.delete_limit_ip(ip, port)
                else:
                    print("Error in action type !")
                    exit(1)
        return self
    


LIST_OF_IP_UFW_RULES = [
    {
        "ip":"127.0.0.1",
        "port":8080,
        "action":"allow",
        "delete_rule_at_end":False,
        "comment":"localhost allowed to access port 80"
    },
    {
        "ip":"192.168.0.100",
        "port":8080,
        "action":"allow",
        "delete_rule_at_end":True,
        "comment":"workstation allowed to access port 8080"
    }
]

PORT, HOST = 8080, "0.0.0.0"
PATH = './www/default/'

# later... maybe... HOST_NEEDED_BE_ALIVE_FOR_RUN_HTTP_SERVER = ALIVE_TEST_PING_ICMP_FUNCTION(test_repeats_number=3, host_target=""

def get_ip():
    ip = socket.gethostbyname(socket.gethostname())
    return ip

def get_mac():
    mac = Cmd('getmac')()
    return mac


# class to create an static http server
class StaticServer:
    def __init__(self, port=80, path='.', host='0.0.0.0'):
        self.port = port
        self.path = path
        self.host = host
        self.server = None
        self.process = None
    # function to set the port
    def set_port(self, port):
        self.port = port
        return self
    # function to set the path
    def set_path(self, path):
        self.path = path
        return self
    # function to set the host
    def set_host(self, host):
        self.host = host
        return self
    # function to start the server
    def start(self,print_url=True):
        self.process = Process(target=self._start)
        self.process.start()
        if print_url:
            self.show_url()
        return self
    # function to stop the server
    def stop(self):
        self.process.terminate()
        return self
    # function to start the server
    def _start(self):
        self.server = subprocess.check_output('sudo python3 -m http.server {} -d {}'.format(self.port, self.path), shell=True)
        self.server(_bg=True)
        return self
    # function to get the url
    def get_url(self):
        return 'http://{}:{}'.format(self.host, self.port)
    # function named 'show_url' to display the url returned by 'self.get_url()'
    def show_url(self):
        print("The URL is: {}".format(self.get_url()))
        return self
    # process to detect ESSC key pressing event
    def _wait_ESC_key_pressed(self):
        while True:
            if keyboard.is_pressed('esc'):
                self.stop()
                break
        exit(0)
    def wait_ESC_key_pressed(self):
        input("Press ESC to stop the server...")
        # create a new process to detect ESC key pressing event
        self.process = Process(target=self._wait_ESC_key_pressed)
        # start the process
        self.process.start()
        # wait for the process to finish
        self.process.join()
        return self


def main():
    # create an declaration of an new UFW_RulesSetters object named 'firewallSetters' if ENABLE_UFW_RULES_SETTERS
    if ENABLE_UFW_RULES_SETTERS:
        firewallSetters = UFW_RulesSetters()
        # enable ufw firewall service
        firewallSetters.ufw_enable_command()
        # enable ufw firewall by command call function
        firewallSetters.ufw_enable_command()
        # set ufw firewall rules
        firewallSetters.set_ufw_rules(LIST_OF_IP_UFW_RULES).execute_rules_setting_up()
        # show ufw firewall status
        if VERBOSE:
            firewallSetters.ufw_status()

    # create an instance of the StaticServer class
    server = StaticServer()
    # set the port to PORT variable value
    server.set_port(PORT)
    # set the path to PATH variable value
    server.set_path(PATH)
    # set the host to HOST variable value
    server.set_host(HOST)
    # start the server
    server.start()
    # show the url
    server.show_url()
    # call the function of server to start the process call to detect the event of ESC key is pressed and stop the server
    server.wait_ESC_key_pressed()
    # call the firewallSetters function named 'execute_deleting_rules' to delete the rules setted up
    if ENABLE_UFW_RULES_SETTERS:
        firewallSetters.execute_deleting_rules()
    # exit the program
    exit(0)

if __name__ == "__main__":
    main()