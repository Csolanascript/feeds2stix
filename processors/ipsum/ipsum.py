import argparse
import json
import logging
import os
import shutil
import sys
import geoip2.database  # <--- Integrado
from datetime import UTC, datetime

import requests
from stix2 import Bundle, Indicator, IPv4Address

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

IPSUM_FEED_URL_TEMPLATE = (
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/{level}.txt"
)
BASE_OUTPUT_DIR = "outputs/ipsum"

# Rutas de base de datos locales
GEO_DB_PATH = "GeoLite2-City.mmdb"
ASN_DB_PATH = "GeoLite2-ASN.mmdb"

def create_ipsum_identity():
    """Create the IPSum identity object"""
    return create_identity_object(
        name="IPSum",
        description="IPsum is a threat intelligence feed based on 30+ different lists.",
        identity_class="system",
        contact_info="https://github.com/stamparm/ipsum",
    )

def create_ipsum_marking_definition():
    """Create a marking definition for IPSum feed"""
    return create_marking_definition_object("Origin: https://github.com/stamparm/ipsum")

def fetch_ipsum_feed(level):
    """Fetch IP addresses from IPSum feed"""
    url = IPSUM_FEED_URL_TEMPLATE.format(level=level)
    logger.info(f"Fetching IPSum feed level {level}...")
    response = requests.get(url)
    response.raise_for_status()
    ip_addresses = [
        line.strip()
        for line in response.text.splitlines()
        if line.strip() and not line.startswith("#")
    ]
    return ip_addresses

def get_local_enrichment(ip, geo_reader, asn_reader):
    """Enriquece la IP usando City y ASN localmente."""
    metadata = {}
    try:
        # Geo Info
        geo_res = geo_reader.city(ip)
        metadata.update({
            "city": geo_res.city.name,
            "country": geo_res.country.name,
            "country_code": geo_res.country.iso_code, # Vital para Neo4j
            "x_latitude": geo_res.location.latitude,
            "x_longitude": geo_res.location.longitude,
        })
    except: pass

    try:
        # ASN Info
        asn_res = asn_reader.asn(ip)
        metadata.update({
            "asn": asn_res.autonomous_system_number, # Vital para Neo4j
            "x_as_organization": asn_res.autonomous_system_organization,
        })
    except: pass
    return metadata

def create_stix_objects(
    ip_addresses_by_level, ipsum_identity, ipsum_marking, script_run_time, geo_reader, asn_reader
):
    """Create STIX objects for IP addresses with enrichment"""
    stix_objects = []
    enriched_count = 0
    confidence_map = {1: 30, 2: 40, 3: 50, 4: 60, 5: 70, 6: 80, 7: 90, 8: 100}

    ipsum_marking_id = ipsum_marking["id"]
    ipsum_identity_id = ipsum_identity["id"]

    total_ips = sum(len(ips) for ips in ip_addresses_by_level.values())
    processed = 0

    for level in sorted(ip_addresses_by_level.keys(), reverse=True):
        ip_list = ip_addresses_by_level[level]
        confidence = confidence_map.get(level, 50)

        logger.info(f"Processing Level {level} ({len(ip_list)} IPs)...")

        for ip in ip_list:
            processed += 1
            if processed % 2000 == 0:
                logger.info(f"Progress: {processed}/{total_ips} IPs...")

            # Enriquecimiento
            geo_metadata = get_local_enrichment(ip, geo_reader, asn_reader)
            if geo_metadata:
                enriched_count += 1

            ipv4_obj = IPv4Address(
                value=ip,
                custom_properties=geo_metadata,
                allow_custom=True
            )

            indicator_name = f"IPv4: {ip} (IPSum Level {level})"
            indicator_id = f"indicator--{generate_uuid5(indicator_name, namespace=ipsum_marking_id)}"

            indicator = Indicator(
                id=indicator_id,
                created_by_ref=ipsum_identity_id,
                created=script_run_time,
                modified=script_run_time,
                valid_from=script_run_time,
                confidence=confidence,
                indicator_types=["malicious-activity"],
                name=indicator_name,
                pattern=f"[ipv4-addr:value='{ip}']",
                pattern_type="stix",
                object_marking_refs=[
                    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                    ipsum_marking_id,
                ],
            )

            stix_objects.append(ipv4_obj)
            stix_objects.append(indicator)
            stix_objects.append(make_relationship(
                source_ref=indicator.id,
                target_ref=ipv4_obj.id,
                relationship_type="indicates",
                created_by_ref=ipsum_identity_id,
                marking_refs=indicator.object_marking_refs,
                created=script_run_time,
            ))

    return stix_objects, enriched_count

def fetch_all_levels(min_level):
    """Fetch unique IPs across levels"""
    seen_ips = set()
    ip_addresses_by_level = {}
    for level in range(8, min_level - 1, -1):
        ip_addresses = fetch_ipsum_feed(level)
        new_ips = [ip for ip in ip_addresses if ip not in seen_ips]
        for ip in new_ips: seen_ips.add(ip)
        if new_ips:
            ip_addresses_by_level[level] = new_ips
    return ip_addresses_by_level

def main():
    parser = argparse.ArgumentParser(description="Convert IPSum to STIX 2.1 with Geo Enrichment")
    parser.add_argument("--min-level", type=int, required=True, choices=range(1, 9))
    args = parser.parse_args()

    if not os.path.exists(GEO_DB_PATH) or not os.path.exists(ASN_DB_PATH):
        logger.error(f"Faltan bases de datos locales: {GEO_DB_PATH} o {ASN_DB_PATH}")
        return 1

    try:
        output_dir, _ = setup_output_directory(BASE_OUTPUT_DIR, clean=True)
        script_run_time = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        feeds2stix_marking = fetch_external_objects()
        
        ipsum_identity = create_ipsum_identity()
        ipsum_marking = create_ipsum_marking_definition()

        ip_addresses_by_level = fetch_all_levels(args.min_level)

        logger.info("Starting enrichment and STIX object creation...")
        
        # Abrimos los lectores una sola vez
        with geoip2.database.Reader(GEO_DB_PATH) as geo_reader, \
             geoip2.database.Reader(ASN_DB_PATH) as asn_reader:

            stix_objects, total_enriched = create_stix_objects(
                ip_addresses_by_level, ipsum_identity, ipsum_marking, 
                script_run_time, geo_reader, asn_reader
            )

        logger.info("Creating STIX bundle...")
        bundle = create_bundle_with_metadata(
            stix_objects, ipsum_identity, ipsum_marking, feeds2stix_marking
        )

        bundle_path = save_bundle_to_file(bundle, output_dir, f"ipsum_level_{args.min_level}")

        # Resumen
        print("\n" + "═"*50)
        print(f"📊 RESUMEN: IPSUM ENRICHMENT")
        print("─" * 50)
        print(f"IPs procesadas:             {sum(len(ips) for ips in ip_addresses_by_level.values())}")
        print(f"IPs localizadas (Geo/ASN):  {total_enriched}")
        print(f"Bundle guardado en:         {bundle_path}")
        print("═"*50 + "\n")

        return 0

    except Exception as e:
        logger.error(f"Error processing IPSum feed: {e}", exc_info=True)
        return 1

if __name__ == "__main__":
    sys.exit(main())