import csv
import re

from .base import *



class ZmapAssetInventoryForm(ComponentForm):

    assets_file = forms.FileField(
        label='Assets File',
        widget=forms.FileInput,
        required=True
    )
    field_order = ['name', 'summary', 'pageBreakBefore', 'showTitle', 'assets_file']


class Component(BaseComponent):

    default_name = 'Zmap Asset Inventory'
    formClass = ZmapAssetInventoryForm

    # the "templatable" attribute decides whether or not that field
    # gets saved if the report is ever converted into a template
    fieldList = {}

    # make sure to specify the HTML template
    htmlTemplate = 'componentTemplates/ZmapAssetInventory.html'

    # Font Awesome icon type + color (HTML/CSS)
    # This is just eye candy in the web app
    iconType = 'fas fa-stream'
    iconColor = 'var(--blue)'

    # the "preprocess" function is executed when the report is rendered
    # use this to perform any last-minute operations on its data
    def preprocess(self, context):
        # TODO Figure out why files can't upload and move the processing logic to the save method.

        context['assets'] = []
        try:
            # TODO change this to use the uploaded file, once we figure out Django/Writehat issue.
            csv_filename = "example_asset.csv"
            # TODO ensure that the csv file is in the expected ZMAP format.
            with open(csv_filename, 'r') as csv_file:
                reader = csv.DictReader(csv_file)
                for row in reader:
                    new_row = parse_row(row)
                    context['assets'].append(new_row)

        except:
            log.exception("Error parsing ZMAP asset CSV.")

        return context

def parse_row(row):
    # Format column names for easier parsing in template.
    new_row = {}
    for key in row.keys():
        new_key = key.replace(' ', '_').lower()
        new_row[new_key] = row[key]

    log.info(new_row)

    # Parse tools.
    tools_columns = [
        'wmi',
        'defender',
        'symantec',
        'altiris',
        'cisco_fireamp',
        'cisco_anyconnect',
        'snare',
        'malwarebytes',
        'ivanti',
        'sophos',
        'webroot',
        'kaseya',
        'carbon_black',
        'red_cloak',
        'splunk',
        'bitdefender',
        'solarwinds',
        'crowdstrike',
    ]

    host_tools = []
    for tools_column in tools_columns:
        if tools_column in new_row:
            if len(new_row[tools_column]) > 0:
                host_tools.append(tools_column)
            # Remove, no need to pass to frontend.
            new_row.pop(tools_column)

    if len(host_tools) > 0:
        new_row['installed_tools'] = ", ".join(host_tools)
    else:
        new_row['installed_tools'] = "None found"

    # Parse vulnerabilities.
    vuln_columns = [
        'vulnerable_to_eternalblue',
    ]

    host_vulns = []
    for vuln_column in vuln_columns:
        if vuln_column in new_row:
            if len(new_row[vuln_column]) > 0:
                host_vulns.append(vuln_column)
            # Remove, no need to pass to frontend.
            new_row.pop(vuln_column)

    if len(host_vulns) > 0:
        new_row['vulnerabilities'] = ", ".join(host_vulns)
    else:
        new_row['vulnerabilities'] = "None found"

    # Parse open ports.
    # We will use regex here because there may be unique portscan requirements.
    port_columns = []
    for column in new_row.keys():
        # TODO Determine if we need to actually validate the port (ex. 1 - 65535)
        match_port = re.match(r'^\d+(?:/tcp.*|/udp)?$', column)
        if len(match_port) > 0:
            port_columns.append(column)

    host_ports = []
    for port_column in port_columns:
        if port_column in new_row:
            if new_row[port_column] == "Open":
                host_ports.append(port_column)
            # Remove, no need to pass to frontend.
            new_row.pop(port_column)

    if len(host_ports) > 0:
        new_row['open_ports'] = ", ".join(host_ports)
    else:
        new_row['open_ports'] = "None found"

    # Parse default creds.
    default_cred_columns = [
        'default_ssh_login',
        'open_ftp',
        'open_nfs',
        'open_vnc',
    ]

    host_default_creds = []
    for default_cred_column in default_cred_columns:
        if default_cred_column in new_row:
            if len(new_row[default_cred_column]) > 0:
                host_default_creds.append(default_cred_column)
            # Remove, no need to pass to frontend.
            new_row.pop(default_cred_column)

    if len(host_default_creds) > 0:
        new_row['default_creds'] = ", ".join(host_default_creds)
    else:
        new_row['default_creds'] = "None found"

    return new_row



