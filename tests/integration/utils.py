# Copyright 2025 Canonical Ltd
# See LICENSE file for licensing details.

import asyncio
import json
import logging
from pathlib import Path
from typing import Dict, cast

import requests
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from juju.unit import Unit
from oauth_tools import ExternalIdpService
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)
METADATA = yaml.safe_load(Path("./metadata.yaml").read_text())
APP_NAME = "juju-jimm-k8s"
HTTP_INGRESS_APP_NAME = "traefik"
HTTP_INGRESS_SERVICE_NAME = "traefik-lb"
IDENTITY_PLATFORM_APPS = [
    "hydra",
    "kratos",
    "identity-platform-login-ui-operator",
    "postgresql-k8s",
    "self-signed-certificates",
    "traefik-admin",
    "traefik-public",
]
IDENTITY_FOUNDATIONAL_APPS = [
    "postgresql-k8s",
    "self-signed-certificates",
    "traefik-admin",
    "traefik-public",
]
IDENTITY_PLATFORM_ALL_APPS = IDENTITY_PLATFORM_APPS + ["kratos-external-idp-integrator"]
IDENTITY_TRAEFIK_PLACEHOLDER_HOSTS = {
    "traefik-admin": "traefik-admin.localhost",
    "traefik-public": "traefik-public.localhost",
}
IDENTITY_ROUTE_DEPENDENT_RELATIONS = [
    ("kratos:hydra-endpoint-info", "hydra:hydra-endpoint-info"),
    (
        "identity-platform-login-ui-operator:hydra-endpoint-info",
        "hydra:hydra-endpoint-info",
    ),
    (
        "identity-platform-login-ui-operator:ui-endpoint-info",
        "hydra:ui-endpoint-info",
    ),
    (
        "identity-platform-login-ui-operator:ui-endpoint-info",
        "kratos:ui-endpoint-info",
    ),
    ("identity-platform-login-ui-operator:kratos-info", "kratos:kratos-info"),
]
SELF_SIGNED_CA_SECRET_LABEL = "ca-certificates"
JIMM_REQUEST_KWARGS = {"timeout": 30}


def get_jimm(jimm_address: str, url_path: str, **kwargs) -> requests.Response:
    """Query the externally exposed JIMM endpoint."""
    request_kwargs = {**JIMM_REQUEST_KWARGS, **kwargs}
    if jimm_address.startswith("https://"):
        request_kwargs.setdefault("verify", False)
    return requests.get(f"{jimm_address.rstrip('/')}{url_path}", **request_kwargs)


async def get_unit_data(ops_test: OpsTest, unit_name: str) -> dict:
    _, stdout, _ = await ops_test.juju("show-unit", unit_name)
    cmd_output = yaml.safe_load(stdout)
    return cmd_output[unit_name]


async def get_app_config(ops_test: OpsTest, app_name: str) -> dict:
    _, stdout, _ = await ops_test.juju("config", app_name, "--format=yaml")
    return yaml.safe_load(stdout)


async def list_secrets(ops_test: OpsTest) -> dict:
    _, stdout, _ = await ops_test.juju("list-secrets", "--format=yaml")
    return yaml.safe_load(stdout)


async def show_secret(ops_test: OpsTest, secret_id: str) -> dict:
    _, stdout, _ = await ops_test.juju("show-secret", secret_id, "--reveal", "--format=yaml")
    return yaml.safe_load(stdout)


async def get_ca_secret_content(ops_test: OpsTest) -> dict:
    secrets = await list_secrets(ops_test)
    secret_id = next(
        secret_id
        for secret_id, metadata in secrets.items()
        if metadata.get("owner") == "self-signed-certificates"
        and metadata.get("label") == SELF_SIGNED_CA_SECRET_LABEL
    )
    secret = await show_secret(ops_test, secret_id)
    return secret[secret_id]["content"]


def build_signed_certificate(
    ca_certificate_pem: str,
    ca_private_key_pem: str,
    ca_private_key_password: str,
    hostname: str,
    extra_hostnames: list[str] | None = None,
) -> tuple[str, str]:
    """Generate a leaf certificate signed by the self-signed-certificates CA."""
    ca_cert = x509.load_pem_x509_certificate(ca_certificate_pem.encode())
    ca_key = cast(
        rsa.RSAPrivateKey,
        serialization.load_pem_private_key(
        ca_private_key_pem.encode(),
        password=ca_private_key_password.encode(),
        ),
    )
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    names = [hostname]
    if extra_hostnames:
        names.extend(extra_hostnames)
    unique_names = sorted(set(names))

    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(ca_cert.not_valid_before_utc)
        .not_valid_after(ca_cert.not_valid_after_utc)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in unique_names]),
            critical=False,
        )
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    certificate_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    return certificate_pem, private_key_pem


async def configure_traefik_tls(
    ops_test: OpsTest,
    app_name: str,
    hostname: str,
    extra_hostnames: list[str] | None = None,
) -> None:
    """Configure a Traefik app with a CA-signed certificate for the given hostnames."""
    ca_secret = await get_ca_secret_content(ops_test)
    certificate_pem, private_key_pem = build_signed_certificate(
        ca_certificate_pem=ca_secret["ca-certificate"],
        ca_private_key_pem=ca_secret["private-key"],
        ca_private_key_password=ca_secret["private-key-password"],
        hostname=hostname,
        extra_hostnames=extra_hostnames,
    )
    await ops_test.model.applications[app_name].set_config(
        {
            "external_hostname": hostname,
            "tls-cert": certificate_pem,
            "tls-key": private_key_pem,
            "tls-ca": ca_secret["ca-certificate"],
        }
    )


async def configure_traefik_http(
    ops_test: OpsTest,
    app_name: str,
    hostname: str,
) -> None:
    """Configure a Traefik app to publish an HTTP host without TLS termination."""
    await ops_test.model.applications[app_name].set_config({"external_hostname": hostname})


async def get_jimm_address(ops_test: OpsTest) -> str:
    """Return the external HTTP URL for JIMM."""
    data = await get_unit_data(ops_test, f"{APP_NAME}/0")
    ingress_relation = next(
        (integration for integration in data["relation-info"] if integration["endpoint"] == "ingress"),
        None,
    )
    if not ingress_relation:
        raise RuntimeError("JIMM ingress relation is not present")

    ingress_data = ingress_relation.get("application-data", {}).get("ingress")
    if ingress_data:
        return json.loads(ingress_data)["url"].rstrip("/")

    jimm_address = await get_traefik_address(ops_test, HTTP_INGRESS_APP_NAME, HTTP_INGRESS_SERVICE_NAME)
    return jimm_address.rstrip("/")


async def wait_for_jimm_address(ops_test: OpsTest, timeout: int = 300) -> str:
    """Wait until Traefik publishes a reachable JIMM HTTP URL."""
    last_error: Exception | None = None
    attempts = max(1, timeout // 5)

    for _ in range(attempts):
        try:
            jimm_address = await get_jimm_address(ops_test)
            response = get_jimm(jimm_address, "/macaroons/publickey")
            if response.status_code == 200:
                return jimm_address
            last_error = RuntimeError(
                f"unexpected status from JIMM smoke check: {response.status_code}"
            )
        except (requests.RequestException, RuntimeError, KeyError, json.JSONDecodeError) as exc:
            last_error = exc
        await asyncio.sleep(5)

    raise RuntimeError("timed out waiting for JIMM Traefik ingress") from last_error


async def get_service_external_ip(ops_test: OpsTest, service_name: str) -> str:
    """Return the external IP assigned to a service in the current model namespace."""
    namespace = ops_test.model_name
    if namespace is None:
        raise RuntimeError("ops_test.model_name is not available")

    _, stdout, _ = await ops_test.run(
        "kubectl",
        "get",
        "svc",
        "-n",
        namespace,
        service_name,
        "-o",
        "jsonpath={.status.loadBalancer.ingress[0].ip}",
    )
    external_ip = stdout.strip()
    if not external_ip:
        raise RuntimeError(f"service {service_name} does not have an external IP")
    return external_ip


async def wait_for_service_external_ip(ops_test: OpsTest, service_name: str, timeout: int = 300) -> str:
    """Wait until a service in the current model namespace has an external IP."""
    last_error: Exception | None = None
    attempts = max(1, timeout // 5)

    for _ in range(attempts):
        try:
            return await get_service_external_ip(ops_test, service_name)
        except RuntimeError as exc:
            last_error = exc
        await asyncio.sleep(5)

    raise RuntimeError(f"timed out waiting for service {service_name} external IP") from last_error


async def wait_for_applications(
    ops_test: OpsTest,
    app_names: list[str],
    timeout: int = 2000,
) -> None:
    """Wait for a set of applications to reach active using Juju CLI polling.

    This avoids libjuju watcher churn and also tolerates transient hook failures
    while applications are still converging.
    """
    deadline = asyncio.get_running_loop().time() + timeout
    last_snapshot = ""

    while True:
        _, stdout, _ = await ops_test.juju("status", "--format=yaml")
        status = yaml.safe_load(stdout)
        applications = status.get("applications", {})

        pending = []
        snapshot_lines = []
        for app_name in app_names:
            app = applications.get(app_name)
            if not app:
                pending.append(app_name)
                snapshot_lines.append(f"{app_name}: missing")
                continue

            app_status = app.get("application-status", {}).get("current")
            units = app.get("units", {})
            unit_states = [
                f"{unit_name}={unit.get('workload-status', {}).get('current')}/{unit.get('juju-status', {}).get('current')}"
                for unit_name, unit in units.items()
            ]
            snapshot_lines.append(
                f"{app_name}: app={app_status} units={', '.join(unit_states) or 'none'}"
            )
            if app_status != "active":
                pending.append(app_name)

        if not pending:
            return

        last_snapshot = "\n".join(snapshot_lines)
        if asyncio.get_running_loop().time() >= deadline:
            raise RuntimeError(
                "timed out waiting for applications to become active:\n" + last_snapshot
            )
        await asyncio.sleep(5)


async def get_traefik_address(
    ops_test: OpsTest,
    traefik_app_name: str,
    service_name: str,
    app_name: str = APP_NAME,
) -> str:
    """Build the expected Traefik ingress URL for an application."""
    if ops_test.model_name is None:
        raise RuntimeError("ops_test.model_name is not available")

    config = await get_app_config(ops_test, traefik_app_name)
    settings = config.get("settings", {})
    routing_mode = settings.get("routing_mode", {}).get("value")
    external_hostname = settings.get("external_hostname", {}).get("value")
    external_ip = await get_service_external_ip(ops_test, service_name)

    if routing_mode == "subdomain":
        if not external_hostname:
            external_hostname = f"{external_ip}.sslip.io"
        return f"https://{ops_test.model_name}-{app_name}.{external_hostname}"

    return f"https://{external_ip}/{ops_test.model_name}-{app_name}"


async def get_unit_by_name(unit_name: str, unit_index: str, unit_list: Dict[str, Unit]) -> Unit:
    return unit_list.get("{unitname}/{unitindex}".format(unitname=unit_name, unitindex=unit_index))


async def deploy_identity_bundle(
    ops_test: OpsTest,
    bundle_url: str,
    ext_idp_service: ExternalIdpService,
) -> None:
    """Deploy and configure the identity bundle used by integration tests."""
    await ops_test.run("juju", "deploy", bundle_url, "--trust")

    await asyncio.gather(
        *[
            ops_test.model.applications[app_name].set_config({"external_hostname": hostname})
            for app_name, hostname in IDENTITY_TRAEFIK_PLACEHOLDER_HOSTS.items()
        ]
    )

    logger.info("Waiting for foundational identity applications")
    await wait_for_applications(ops_test, IDENTITY_FOUNDATIONAL_APPS)

    admin_external_ip = await wait_for_service_external_ip(ops_test, "traefik-admin-lb")
    public_external_ip = await wait_for_service_external_ip(ops_test, "traefik-public-lb")
    await asyncio.gather(
        configure_traefik_http(ops_test, "traefik-admin", f"{admin_external_ip}.sslip.io"),
        configure_traefik_tls(ops_test, "traefik-public", f"{public_external_ip}.sslip.io", ["traefik-public.localhost"]),
    )

    # Hydra dev mode is only needed during the placeholder-host bootstrap.
    await ops_test.juju("config", "hydra", "dev=false")

    logger.info("Adding route-dependent identity relations")
    for endpoint_one, endpoint_two in IDENTITY_ROUTE_DEPENDENT_RELATIONS:
        await ops_test.model.integrate(endpoint_one, endpoint_two)

    await wait_for_applications(ops_test, IDENTITY_PLATFORM_APPS)

    logger.info("Configuring the identity platform")
    await ops_test.juju(
        "config",
        "kratos-external-idp-integrator",
        f"client_id={ext_idp_service.client_id}",
        f"client_secret={ext_idp_service.client_secret}",
        "provider=generic",
        f"issuer_url={ext_idp_service.issuer_url}",
        "scope=profile email",
        "provider_id=Dex",
    )
    await wait_for_applications(ops_test, IDENTITY_PLATFORM_ALL_APPS)

    redirect_uri_action = await ops_test.model.applications["kratos-external-idp-integrator"].units[0].run_action(
        "get-redirect-uri"
    )
    action_output = await redirect_uri_action.wait()
    assert "redirect-uri" in action_output.results
    ext_idp_service.update_redirect_uri(redirect_uri=action_output.results["redirect-uri"])


async def deploy_jimm(
    ops_test: OpsTest,
    charm: Path,
    hydra_app_name: str,
    public_traefik_app_name: str,
    self_signed_certificates_app_name: str,
    ext_idp_service: ExternalIdpService,
) -> None:
    """(Optionally) Build and then deploy JIMM and all dependencies.

    Args:
        ops_test (OpsTest): Fixture for testing operator charms
        charm (Path): Path to prebuilt charm
    """
    # Build and deploy charm from local source folder
    # (Optionally build) and deploy charm from local source folder
    jimm_image_path = METADATA["resources"]["jimm-image"]["upstream-source"]
    resources = {"jimm-image": jimm_image_path}

    # Deploy the identity bundle first because it checks everything is in an active state and if we deploy JIMM apps
    # at the same time, then that check will fail.
    logger.info("deploying identity bundle")
    bundle_path = Path(__file__).parent / "identity-bundle.yaml"
    await deploy_identity_bundle(ops_test=ops_test, bundle_url=str(bundle_path), ext_idp_service=ext_idp_service)

    # Deploy the charm and wait for active/idle status
    logger.info("deploying charms")
    async with ops_test.fast_forward():
        await asyncio.gather(
            ops_test.model.deploy(
                charm,
                resources=resources,
                application_name=APP_NAME,
                config={
                    "uuid": "f4dec11e-e2b6-40bb-871a-cc38e958af49",
                    "dns-name": "",
                    "public-key": "izcYsQy3TePp6bLjqOo3IRPFvkQd2IKtyODGqC6SdFk=",
                    "private-key": "ly/dzsI9Nt/4JxUILQeAX79qZ4mygDiuYGqc2ZEiDEc=",
                    "postgres-secret-storage": True,
                    "secure-session-cookies": True,
                    "juju-dashboard-location": "http://localhost/debug/info",
                },
                num_units=1,
            ),
            ops_test.model.deploy(
                "postgresql-k8s",
                application_name="jimm-db",
                channel="14/stable",
            ),
            ops_test.model.deploy(
                "openfga-k8s",
                application_name="openfga",
                channel="latest/stable",
            ),
            ops_test.model.deploy(
                "traefik-k8s",
                application_name="traefik",
                channel="latest/stable",
                config={"external_hostname": "traefik.localhost"},
            ),
        )

    logger.info("waiting for postgresql")
    await wait_for_applications(ops_test, ["jimm-db"])

    logger.info("adding custom ca cert relation")
    await ops_test.model.integrate("{}:receive-ca-cert".format(APP_NAME), self_signed_certificates_app_name)

    logger.info("adding openfga postgresql relation")
    await ops_test.model.integrate("openfga:database", "jimm-db:database")

    logger.info("adding openfga relation")
    await ops_test.model.integrate(f"{APP_NAME}:openfga", "openfga")

    logger.info("adding postgresql relation")
    await ops_test.model.integrate(APP_NAME, "jimm-db:database")

    logger.info("adding oauth relation")
    await ops_test.model.integrate(f"{APP_NAME}:oauth", hydra_app_name)

    logger.info("configuring dedicated traefik http ingress")
    traefik_external_ip = await wait_for_service_external_ip(ops_test, HTTP_INGRESS_SERVICE_NAME)
    await ops_test.model.applications[HTTP_INGRESS_APP_NAME].set_config({"routing_mode": "subdomain"})
    await configure_traefik_tls(
        ops_test,
        HTTP_INGRESS_APP_NAME,
        f"{traefik_external_ip}.sslip.io",
        ["traefik.localhost"],
    )

    logger.info("adding traefik http relation")
    await ops_test.model.integrate(f"{APP_NAME}:ingress", HTTP_INGRESS_APP_NAME)

    logger.info("adding traefik ssh relation")
    await ops_test.model.integrate(f"{APP_NAME}:ingress-ssh", HTTP_INGRESS_APP_NAME)

    await ops_test.model.wait_for_idle(timeout=2000)

    expected_jimm_address = await get_traefik_address(
        ops_test,
        HTTP_INGRESS_APP_NAME,
        HTTP_INGRESS_SERVICE_NAME,
    )
    logger.info("setting JIMM public URL to %s", expected_jimm_address)
    await ops_test.juju(
        "config",
        APP_NAME,
        f"dns-name={expected_jimm_address}",
        f"juju-dashboard-location={expected_jimm_address}/debug/info",
    )

    await ops_test.model.wait_for_idle(timeout=2000)
    jimm_address = await wait_for_jimm_address(ops_test)
    macaroon_publickey = get_jimm(jimm_address, "/macaroons/publickey")
    assert macaroon_publickey.status_code == 200
