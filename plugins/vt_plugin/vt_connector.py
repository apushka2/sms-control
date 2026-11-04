import json
import os
from urllib.parse import quote

import vt


class VTConnector:
    def __init__(self, api_key: str | None = None):
        configured_api_key = api_key or os.getenv("VT_API_KEY")
        if not configured_api_key or not configured_api_key.strip():
            raise ValueError(
                "VirusTotal API key is required. Set the VT_API_KEY environment variable."
            )

        self.client = vt.Client(configured_api_key.strip())

    def get_hash_report(self, file_hash: str) -> str:
        file_hash = file_hash.strip()
        if not file_hash:
            return "A file hash is required."
        return self._get_report(f"/files/{quote(file_hash, safe='')}", "file")

    def get_url_report(self, url: str) -> str:
        url = url.strip()
        if not url:
            return "A URL is required."
        url_id = quote(vt.url_id(url), safe="")
        return self._get_report(f"/urls/{url_id}", "URL")

    def get_ip_report(self, ip: str) -> str:
        ip = ip.strip()
        if not ip:
            return "An IP address is required."
        return self._get_report(
            f"/ip_addresses/{quote(ip, safe='')}", "IP address"
        )

    def get_domain_report(self, domain: str) -> str:
        domain = domain.strip()
        if not domain:
            return "A domain is required."
        return self._get_report(f"/domains/{quote(domain, safe='')}", "domain")

    def get_private_report(self, resource: str) -> str:
        resource = resource.strip().strip("/")
        if resource.startswith("private/"):
            resource = resource[len("private/") :]
        if not resource:
            return "A private file hash or resource is required."

        if "/" not in resource:
            resource = f"files/{resource}"
        elif len(resource.split("/")) != 2 or resource.split("/", 1)[0] not in {
            "files",
            "urls",
        }:
            return "Use a private file hash, files/<hash>, or urls/<url_id>."

        resource_path = "/".join(quote(part, safe="") for part in resource.split("/"))
        return self._get_report(f"/private/{resource_path}", "private")

    def close(self) -> None:
        self.client.close()

    def _get_report(self, path: str, resource_type: str) -> str:
        try:
            report = self.client.get_object(path)
            return json.dumps(report.to_dict(), indent=2, sort_keys=True)
        except vt.error.APIError as error:
            return f"VirusTotal API error retrieving {resource_type} report: {error}"
