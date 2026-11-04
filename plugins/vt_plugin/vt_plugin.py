from plugins.plugin import Plugin
from plugins.vt_plugin.vt_connector import VTConnector

class VTPlugin(Plugin):
    def __init__(self):
        super().__init__()
        self.connector = VTConnector()

        self.tools = {
            'vt_file_report': {
                'method': self.connector.get_hash_report,
                'description': 'Get a VirusTotal file report. Takes an MD5, SHA-1, or SHA-256 hash.'
            },
            'vt_url_report': {
                'method': self.connector.get_url_report,
                'description': 'Get a VirusTotal URL report. Takes the full URL.'
            },
            'vt_ip_report': {
                'method': self.connector.get_ip_report,
                'description': 'Get a VirusTotal IP address report. Takes an IPv4 or IPv6 address.'
            },
            'vt_domain_report': {
                'method': self.connector.get_domain_report,
                'description': 'Get a VirusTotal domain report. Takes a domain name.'
            },
            'vt_private_report': {
                'method': self.connector.get_private_report,
                'description': 'Get a VirusTotal private file or URL report. Takes a file hash, files/<hash>, or urls/<url_id>.'
            }
        }

    def close(self) -> None:
        self.connector.close()