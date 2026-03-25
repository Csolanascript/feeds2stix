import argparse
import json
import logging
import os
import sys
import geoip2.database  # <--- Integrado para lectura local
from datetime import UTC, datetime

import requests
from stix2 import Indicator, IPv4Address

from helpers.utils import (
    create_bundle_with_metadata,
    create_identity_object,
    create_marking_definition_object,
    fetch_external_objects,
    generate_uuid5,
    make_relationship,
    save_bundle_to_file,
    setup_output_directory,
)

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

CINSSCORE_FEED_URL = "https://cinsscore.com/list/ci-badguys.txt"
BASE_OUTPUT_DIR = "outputs/cinsscore"

# Rutas de base de datos locales
GEO_DB_PATH = "GeoLite2-City.mmdb"
ASN_DB_PATH = "GeoLite2-ASN.mmdb"


def create_cinsscore_identity():
    """Create the CINS Score identity object"""
    return create_identity_object(
        name="CINS",
        description='Collective Intelligence Network Security (CINS Army) effort to significantly improve network security and provide vital information to the community.',
        identity_class="system",
        contact_info="https://cinsarmy.com/",
    )


def create_cinsscore_marking_definition():
    """Create a marking definition for CINS Score feed"""
    return create_marking_definition_object(f"Origin: {CINSSCORE_FEED_URL}")


def fetch_cinsscore_feed():
    """Fetch IP addresses from CINS Score feed"""
    logger.info(f"Fetching CINS Score feed from: {CINSSCORE_FEED_URL}")
    response = requests.get(CINSSCORE_FEED_URL)
    response.raise_for_status()
    ip_addresses = [
        line.strip()
        for line in response.text.splitlines()
        if line.strip() and not line.startswith("#")
    ]
    logger.info(f"Found {len(ip_addresses)} IP addresses in CINS Score feed")
    return ip_addresses


def get_local_enrichment(ip, geo_reader, asn_reader):
    """Enriquece la IP usando City y ASN localmente para Neo4j."""
    metadata = {}
    # 1. Información Geográfica
    try:
        geo_res = geo_reader.city(ip)
        metadata.update({
            "city": geo_res.city.name,
            "country": geo_res.country.name,
            "country_code": geo_res.country.iso_code, # Clave vital para Neo4j
            "x_latitude": geo_res.location.latitude,
            "x_longitude": geo_res.location.longitude,
        })
    except Exception:
        pass

    # 2. Información de ASN (Empresa/Red)
    try:
        asn_res = asn_reader.asn(ip)
        metadata.update({
            "asn": asn_res.autonomous_system_number, # Clave vital para Neo4j
            "x_as_organization": asn_res.autonomous_system_organization,
        })
    except Exception:
        pass

    return {k: v for k, v in metadata.items() if v is not None}


def create_stix_objects(
    ip_addresses, cinsscore_identity, cinsscore_marking, script_run_time, geo_reader, asn_reader
):
    """Create STIX objects for IP addresses with local enrichment"""
    stix_objects = []
    enriched_count = 0

    cinsscore_marking_id = cinsscore_marking["id"]
    cinsscore_identity_id = cinsscore_identity["id"]

    logger.info(f"Processing {len(ip_addresses)} IP addresses...")

    for idx, ip in enumerate(ip_addresses):
        if (idx + 1) % 2000 == 0:
            logger.info(f"Processed {idx + 1}/{len(ip_addresses)} IP addresses...")

        # Obtener metadata local
        geo_metadata = get_local_enrichment(ip, geo_reader, asn_reader)
        if geo_metadata:
            enriched_count += 1

        # Crear objeto IP con los campos personalizados para Neo4j
        ipv4_obj = IPv4Address(
            value=ip,
            custom_properties=geo_metadata,
            allow_custom=True
        )

        indicator_name = f"IPv4: {ip}"
        indicator_id = f"indicator--{generate_uuid5(indicator_name, namespace=cinsscore_marking_id)}"

        indicator = Indicator(
            id=indicator_id,
            created_by_ref=cinsscore_identity_id,
            created=script_run_time,
            modified=script_run_time,
            valid_from=script_run_time,
            indicator_types=["malicious-activity"],
            name=indicator_name,
            pattern=f"[ipv4-addr:value='{ip}']",
            pattern_type="stix",
            object_marking_refs=[
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                cinsscore_marking_id,
            ],
        )

        stix_objects.append(ipv4_obj)
        stix_objects.append(indicator)
        
        relationship = make_relationship(
            source_ref=indicator.id,
            target_ref=ipv4_obj.id,
            relationship_type="indicates",
            created_by_ref=cinsscore_identity_id,
            marking_refs=indicator.object_marking_refs,
            created=script_run_time,
        )
        stix_objects.append(relationship)

    return stix_objects, enriched_count


def main():
    parser = argparse.ArgumentParser(description="Convert CINS Score to STIX 2.1")
    args = parser.parse_args()

    # Verificar bases de datos
    if not os.path.exists(GEO_DB_PATH) or not os.path.exists(ASN_DB_PATH):
        logger.error(f"Faltan bases de datos .mmdb en la raíz del proyecto.")
        return 1

    try:
        output_dir, _ = setup_output_directory(BASE_OUTPUT_DIR, clean=True)
        script_run_time = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        feeds2stix_marking = fetch_external_objects()

        cinsscore_identity = create_cinsscore_identity()
        cinsscore_marking = create_cinsscore_marking_definition()

        ip_addresses = fetch_cinsscore_feed()

        logger.info("Starting enrichment and STIX creation...")
        
        # Abrimos los lectores una sola vez para mayor eficiencia
        with geoip2.database.Reader(GEO_DB_PATH) as geo_reader, \
             geoip2.database.Reader(ASN_DB_PATH) as asn_reader:

            stix_objects, total_enriched = create_stix_objects(
                ip_addresses, cinsscore_identity, cinsscore_marking, 
                script_run_time, geo_reader, asn_reader
            )

        logger.info("Creating STIX bundle...")
        bundle = create_bundle_with_metadata(
            stix_objects,
            cinsscore_identity,
            cinsscore_marking,
            feeds2stix_marking,
        )

        bundle_path = save_bundle_to_file(bundle, output_dir, "cinsscore")

        # --- RESUMEN FINAL ---
        print("\n" + "═"*50)
        print(f"📊 RESUMEN: CINS SCORE ENRICHMENT")
        print("─" * 50)
        print(f"Total IPs descargadas:      {len(ip_addresses)}")
        print(f"IPs localizadas (Geo/ASN):  {total_enriched}")
        print(f"Bundle STIX guardado en:    {bundle_path}")
        print("═"*50 + "\n")

        return 0

    except Exception as e:
        logger.error(f"Error processing CINS Score feed: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())