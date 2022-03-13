import csv
import re

from .base import *

# Shared lists.

TOOLS_COLUMNS = [
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

VULN_COLUMNS = [
    'vulnerable_to_eternalblue',
]

DEFAULT_CRED_COLUMNS = [
    'default_ssh_login',
    'open_ftp',
    'open_nfs',
    'open_vnc',
]

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

        try:
            asset_summary_rows = []
            raw_csv_rows = []
            # TODO change this to use the uploaded file, once we figure out Django/Writehat issue.
            csv_filename = "example_asset.csv"
            # TODO ensure that the csv file is in the expected ZMAP format.
            with open(csv_filename, 'r') as csv_file:
                reader = csv.DictReader(csv_file)
                # We only want to get these once.
                port_columns = get_port_columns(reader.fieldnames)
                for row in reader:
                    # Format column names for easier parsing in template.
                    cleaned_row = {}
                    for key in row.keys():
                        new_key = key.replace(' ', '_').lower()
                        cleaned_row[new_key] = row[key]

                    # Add row to our raw list for stats generation.
                    raw_csv_rows.append(cleaned_row)
                    # Parse row for summary table and add to context.
                    summary_row = parse_summary_row(cleaned_row, port_columns)
                    asset_summary_rows.append(summary_row)

            context['stats'] = generate_stats(raw_csv_rows, port_columns)
            context['assets'] = asset_summary_rows
        except:
            log.exception("Error parsing ZMAP asset CSV.")

        return context


# Takes an asset object and formats for the summary table.
def parse_summary_row(cleaned_row, port_columns):
    # Avoid pass by reference.
    row = cleaned_row.copy()

    # Parse tools.
    host_tools = []
    for tools_column in TOOLS_COLUMNS:
        if tools_column in row:
            if len(row[tools_column]) > 0:
                host_tools.append(tools_column)
            # Remove, no need to pass to frontend.
            row.pop(tools_column)

    if len(host_tools) > 0:
        row['installed_tools'] = ", ".join(host_tools)
    else:
        row['installed_tools'] = "None found"

    # Parse vulnerabilities.
    host_vulns = []
    for vuln_column in VULN_COLUMNS:
        if vuln_column in row:
            if len(row[vuln_column]) > 0:
                host_vulns.append(vuln_column)
            # Remove, no need to pass to frontend.
            row.pop(vuln_column)

    if len(host_vulns) > 0:
        row['vulnerabilities'] = ", ".join(host_vulns)
    else:
        row['vulnerabilities'] = "None found"

    # Parse open ports.
    host_ports = []
    for port_column in port_columns:
        if port_column in row:
            if row[port_column] == "Open":
                host_ports.append(port_column)
            # Remove, no need to pass to frontend.
            row.pop(port_column)

    if len(host_ports) > 0:
        row['open_ports'] = ", ".join(host_ports)
    else:
        row['open_ports'] = "None found"

    # Parse default creds.
    host_default_creds = []
    for default_cred_column in DEFAULT_CRED_COLUMNS:
        if default_cred_column in row:
            if len(row[default_cred_column]) > 0:
                host_default_creds.append(default_cred_column)
            # Remove, no need to pass to frontend.
            row.pop(default_cred_column)

    if len(host_default_creds) > 0:
        row['default_creds'] = ", ".join(host_default_creds)
    else:
        row['default_creds'] = "None found"

    return row


# Generates the statistics section of the report.
def generate_stats(raw_csv_rows, port_columns):
    stats = []

    # OS Breakdown
    os_breakdown = {}
    os_breakdown['section_title'] = 'OS Breakdown'
    os_breakdown['section_class'] = os_breakdown['section_title'].replace(' ', '_').lower()
    os_breakdown['table_headers'] = ['OS', 'Occurrences', 'Percentage']
    os_breakdown['distribution'] = {}

    # Port Breakdown
    port_breakdown = {}
    port_breakdown['section_title'] = 'Open Port Breakdown'
    port_breakdown['section_class'] = port_breakdown['section_title'].replace(' ', '_').lower()
    port_breakdown['table_headers'] = ['Port', 'Occurrences', 'Percentage']
    port_breakdown['distribution'] = {}

    # Churn through rows.
    for row in raw_csv_rows:
        # OS Breakdown
        if row['os'] not in os_breakdown['distribution']:
            os_breakdown['distribution'][row['os']] = {
                'occurrences': 0,
                'percentage': 0.0,
            }
        os_breakdown['distribution'][row['os']]['occurrences'] += 1

        # Port Breakdown
        for column in port_columns:
            if row[column] == "Open":
                if column not in port_breakdown['distribution']:
                    port_breakdown['distribution'][column] = {
                        'occurrences': 0,
                        'percentage': 0.0,
                    }
                port_breakdown['distribution'][column]['occurrences'] += 1

    # Calculate percentages.
    total_rows = len(raw_csv_rows)

    # OS Breakdown
    for row in os_breakdown['distribution'].values():
        row['percentage'] = "{0}%".format(round((row['occurrences'] / total_rows) * 100))
    stats.append(os_breakdown)

    # Port Breakdown
    # Note this will be "percentage of total assets" rather than "percentage of open port assets"
    # TODO review logic with client.
    for row in port_breakdown['distribution'].values():
        row['percentage'] = "{0}%".format(round((row['occurrences'] / total_rows) * 100))
    stats.append(port_breakdown)

    # stats.append({
    #     'section_title': 'Default Credentials',
    # })

    # stats.append({
    #     'section_title': 'EDR/AV tools',
    # })

    # stats.append({
    #     'section_title': 'other security controls (iboss, bigfix, etc.)',
    # })

    return stats


# Helper for getting the port columns of a given asset row.
def get_port_columns(columns):
    # Parse open ports.
    # We will use regex here because there may be unique portscan requirements.
    port_columns = []
    for column in columns:
        # TODO Determine if we need to actually validate the port (ex. 1 - 65535)
        # @See https://stackoverflow.com/questions/40665068/python-regex-match-number-followed-by-string-or-nothing
        match_port = re.match(r'^\d+(?:/tcp.*|/udp)?$', column)
        if match_port:
            port_columns.append(column)

    return port_columns