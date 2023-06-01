#!/var/ossec/framework/python/bin/python3


######## vuln_report.py #######
# 
# This is based on original work from Juan C. Tello
# Description:
#  This wodle (Wazuh module) gives Wazuh the capability to query the manager's
#  API to gather information on the inventory information from all agents.
#
# Configuration:
#
#
#    <wodle name="command">
#      <disabled>no</disabled>
#      <tag>test</tag>
#      <command>/var/ossec/framework/python/bin/python3 /var/ossec/wodles/vuln_report.py --manager WAZUH_MANAGER_IP_ADDRESS --user WAZUH_API_USER --password WAZUH_API_PASSWORD</command>
#      <interval>1d</interval>
#      <ignore_output>yes</ignore_output>
#      <run_on_start>yes</run_on_start>
#      <timeout>0</timeout>
#      <!--
#      <verify_sha256></verify_sha256>
#      -->
#    </wodle>
#
#
###############################

import requests, urllib3, json, argparse
from socket import socket, AF_UNIX, SOCK_DGRAM


requests.packages.urllib3.disable_warnings()
HEADERS={}
VERIFY=False
socketAddr = '/var/ossec/queue/sockets/queue'

def get_token():
    """
    Function to retrieve the Wazuh JWST token for the API
    This was built for Wazuh 4.3.10. For Wazuh 4.4.0 this is expected to change
        to a POST request: https://github.com/wazuh/wazuh/issues/12793
    """
    request_result = requests.get(WAZUH_API + "/security/user/authenticate", auth=(WAZUH_USER, WAZUH_PASS), verify=VERIFY)
    if request_result.status_code == 200:
       token = json.loads(request_result.content.decode())['data']['token']
       HEADERS['Authorization'] = f'Bearer {token}'
    else:
        raise Exception(f"Error obtaining response: {request_result.json()}")

def get_pages(URL,limit=500):
    """
    Function to get navigate all pages of a result in the Wazuh API
    """
    result = []
    offset = 0
    finished = False
    while not finished:
        request = requests.get(URL + f"?limit={limit}&offset={offset}", headers=HEADERS, verify=VERIFY)
        if request.status_code == 200:
            items = json.loads(request.content.decode())['data']
            for i in items['affected_items']:
                result.append(i)
            # If there are more items to be gathered, iterate the offset
            if items['total_affected_items'] > (limit + offset):
                offset = offset + limit
                if (offset + limit) > items['total_affected_items']:
                    limit = items['total_affected_items'] - offset
            else:
                finished = True
        else:
            if request.status_code == 401:
                get_token() # Renew token
            else:
                raise Exception(f"Error obtaining response: {request.json()}")
    return result

def get_non_paged(URL):
    """
    Function to get navigate all pages of a result in the Wazuh API
    """
    result = []
    request = requests.get(URL, headers=HEADERS, verify=VERIFY)
    if request.status_code == 200:
        items = json.loads(request.content.decode())['data']
        for i in items['affected_items']:
            result.append(i)
    else:
        if request.status_code == 401:
            get_token() # Renew token
        else:
            raise Exception(f"Error obtaining response: {request.json()}")
    return result

def get_inventory(agents):
    """
    Function to retrieve the inventory of every agent
    https://documentation.wazuh.com/current/user-manual/api/reference.html#tag/Syscollector
    This function returns a dictionary with an inventory for each agent
    """
    inventory = {}
    for a in agents:
        ID=a['id']
        inventory[ID] = dict( hardware = {}, hotfixes={}, netaddr={}, netiface={}, netproto={}, os={}, packages={}, ports={}, processes={} )

        #inventory[ID]['hotfixes'] = get_pages(WAZUH_API + "/syscollector/" + ID + "/hotfixes")
        #inventory[ID]['netaddr'] = get_pages(WAZUH_API + "/syscollector/" + ID + "/netaddr")
        #inventory[ID]['netiface'] = get_pages(WAZUH_API + "/syscollector/" + ID + "/netiface")
        #inventory[ID]['netproto'] = get_pages(WAZUH_API + "/syscollector/" + ID + "/netproto")
        #inventory[ID]['packages'] = get_pages(WAZUH_API + "/syscollector/" + ID + "/packages")
        #inventory[ID]['ports'] = get_pages(WAZUH_API + "/syscollector/" + ID + "/ports")
        #inventory[ID]['processes'] = get_pages(WAZUH_API + "/syscollector/" + ID + "/processes")
        
        inventory[ID]['hardware'] = get_non_paged(WAZUH_API + "/syscollector/" + ID + "/hardware")[0]
        inventory[ID]['os'] = get_non_paged(WAZUH_API + "/syscollector/" + ID + "/os")[0]

    return inventory

def send_event(msg,agentId,agentName):

    string = f'1:[{agentId}] ({agentName}) any->inventory:{msg}'
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socketAddr)
    sock.send(string.encode())
    sock.close()


if __name__ == "__main__":

    # Parsing arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-m', '--manager', type=str, default='127.0.0.1', help='*Wazuh API IP or DNS name.(def. "127.0.0.1").')
    parser.add_argument('-u', '--user', type=str, default='wazuh-wui', help='*Wazuh API user (def. "wazuh-wui").')
    parser.add_argument('-p', '--password', type=str, default='wazuh-wui', help='*Wazuh API user password (def. "wazuh-wui").')
    args = parser.parse_args()

    WAZUH_IP = args.manager
    WAZUH_USER = args.user
    WAZUH_PASS = args.password
    WAZUH_PORT = 55000
    WAZUH_API=f"https://{WAZUH_IP}:{WAZUH_PORT}"
    
    agents = get_pages(WAZUH_API + f"/agents")
    
    inventory = get_inventory(agents)

    for a in agents:
        ID=a['id']
        NAME=a['name']
        print(inventory[ID])
        send_event(json.dumps(inventory[ID]),ID,NAME)
