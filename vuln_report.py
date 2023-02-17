#!/var/ossec/framework/python/bin/python3
######## vuln_report.py ###########
# Author: Juan C. Tello
# Version: 2022.10.25
# Description:
#  This wodle (Wazuh module) gives Wazuh the capability to query the manager's
#  API to gather information on the current status of all agents regarding the
#  Security Configuration Assessment (SCA) module. 
#
# Configuration:
#
#
###############################

import requests, urllib3, json, argparse, csv, smtplib
from datetime import date
from email.message import EmailMessage


requests.packages.urllib3.disable_warnings()
HEADERS={}
VERIFY=False
DATE=date.today()
reportFilename='/tmp/{}-vulnerabilities-report.csv'.format(DATE)

def get_token():
    """
    Function to retrieve the Wazuh JWST token for the API
    This was built for Wazuh 4.3.9. For Wazuh 4.4.0 this is expected to change
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

def get_vulnerability(agents):
    """
    Function to retrieve the vulnerabilities of every agent
    https://documentation.wazuh.com/current/user-manual/api/reference.html#tag/Vulnerability
    This function returns a dictionary with an list of vulnerabilities for each agent
    """
    vulnerabilities = {}
    for a in agents:
        ID=a['id']
        vulnerabilities[ID] = get_pages(WAZUH_API + f"/vulnerability/" + ID)
    return vulnerabilities


def vulnerabilities_report(vulnerabilities):
    """
    Function that generates a CSV report file with a per-agent list of vulnerabilities
    """
    global reportFilename
    with open(reportFilename, 'w') as csvfile:
        filewriter = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
        filewriter.writerow(['agent.id', 'name', 'cve', 'published', 'condition', 'detection_time', 'severity'])
        for i in vulnerabilities.keys():
            for p in vulnerabilities[i]:
                filewriter.writerow([i, p['name'], p['cve'], p['published'], p['condition'], p['detection_time'], p['severity']])

def sendEmail(sender,destination,subject,body,attachmentFilename,smtpServer):
    msg = EmailMessage()
    msg.set_content(body)
    
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = destination
    
    with open(attachmentFilename, 'rb') as fp:
        data = fp.read()
    msg.add_attachment(data, maintype='text', subtype='plain', filename=attachmentFilename)
    
    s = smtplib.SMTP(smtpServer)
    s.send_message(msg)
    s.quit()

if __name__ == "__main__":

    # Parsing arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-m', '--manager', type=str, default='127.0.0.1', help='*Wazuh API IP or DNS name.(def. "127.0.0.1").')
    parser.add_argument('-u', '--user', type=str, default='wazuh-wui', help='*Wazuh API user (def. "wazuh-wui").')
    parser.add_argument('-p', '--password', type=str, default='wazuh-wui', help='*Wazuh API user password (def. "wazuh-wui").')
    parser.add_argument('-s', '--sender', type=str, default=None, help='Email sender field')
    parser.add_argument('-d', '--destination', type=str, default=None, help='Email destination field')
    parser.add_argument('-S', '--smtpserver', type=str, default='localhost', help='SMTP server to relay message')
    args = parser.parse_args()

    WAZUH_IP = args.manager
    WAZUH_USER = args.user
    WAZUH_PASS = args.password
    WAZUH_PORT = 55000
    WAZUH_API=f"https://{WAZUH_IP}:{WAZUH_PORT}"
    SENDER = args.sender
    DESTINATION = args.destination
    SMTPSERVER = args.smtpserver
    EMAIL_SUBJECT = 'Wazuh Vulnerability Report for {}'.format(DATE)
    EMAIL_BODY = 'Wazuh CSV Vulnerability Report attached'
    

    agents = get_pages(WAZUH_API + f"/agents")
    vulnerabilities = get_vulnerability(agents)
    vulnerabilities_report(vulnerabilities)
    sendEmail(SENDER,DESTINATION,EMAIL_SUBJECT,EMAIL_BODY,reportFilename,SMTPSERVER)


