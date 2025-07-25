from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.gcp.gcp_provider import GcpProvider
from prowler.providers.gcp.lib.service.service import GCPService


class CloudSQL(GCPService):
    def __init__(self, provider: GcpProvider):
        super().__init__("sqladmin", provider)
        self.instances = []
        self._get_instances()

    def _get_instances(self):
        for project_id in self.project_ids:
            try:
                request = self.client.instances().list(project=project_id)
                while request is not None:
                    response = request.execute()

                    for instance in response.get("items", []):
                        public_ip = False
                        for address in instance.get("ipAddresses", []):
                            if address["type"] == "PRIMARY":
                                public_ip = True
                        self.instances.append(
                            Instance(
                                name=instance["name"],
                                version=instance["databaseVersion"],
                                region=instance["region"],
                                ip_addresses=instance.get("ipAddresses", []),
                                public_ip=public_ip,
                                require_ssl=instance["settings"]
                                .get("ipConfiguration", {})
                                .get("requireSsl", False),
                                ssl_mode=instance["settings"]
                                .get("ipConfiguration", {})
                                .get("sslMode", "ALLOW_UNENCRYPTED_AND_ENCRYPTED"),
                                automated_backups=instance["settings"][
                                    "backupConfiguration"
                                ]["enabled"],
                                authorized_networks=instance["settings"]
                                .get("ipConfiguration", {})
                                .get("authorizedNetworks", []),
                                flags=instance["settings"].get("databaseFlags", []),
                                project_id=project_id,
                            )
                        )

                    request = self.client.instances().list_next(
                        previous_request=request, previous_response=response
                    )
            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )


class Instance(BaseModel):
    name: str
    version: str
    ip_addresses: list
    region: str
    public_ip: bool
    authorized_networks: list
    require_ssl: bool
    ssl_mode: str
    automated_backups: bool
    flags: list
    project_id: str
