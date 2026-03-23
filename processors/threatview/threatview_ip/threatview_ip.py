import argparse
import json
import logging
import os
import uuid
from datetime import UTC, datetime

import requests
import geoip2.database  # <--- Integrado para lectura local
from stix2 import Indicator, IPv4Address

from helpers.utils import (
    NAMESPACE_UUID,
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

OASIS_NAMESPACE_UUID = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
THREATVIEW_IP_FEED_URL = "https://threatview.io/Downloads/IP-High-Confidence-Feed.txt"
CHECKPOINT_SIZE = 1000
BASE_OUTPUT_DIR = "outputs/threatview_ip"

# Rutas de base de datos locales (Debes tener estos archivos en la carpeta)
GEO_DB_PATH = "GeoLite2-City.mmdb"
ASN_DB_PATH = "GeoLite2-ASN.mmdb"

def create_threatview_identity():
    return create_identity_object(
        name="ThreatView",
        description="Verified threat feeds for immediate perimeter enforcement across security stacks.",
        identity_class="organization",
        contact_info="https://threatview.io/",
    )

def create_threatview_marking_definition():
    return create_marking_definition_object(f"Origin: {THREATVIEW_IP_FEED_URL}")

def fetch_threatview_feed():
    logger.info(f"Fetching ThreatView IP feed from: {THREATVIEW_IP_FEED_URL}")
    response = requests.get(THREATVIEW_IP_FEED_URL)
    response.raise_for_status()
    ip_addresses = [
        line.strip()
        for line in response.text.splitlines()
        if line.strip() and not line.startswith("#")
    ]
    logger.info(f"Found {len(ip_addresses)} IP addresses in ThreatView feed")
    return ip_addresses

def get_local_enrichment(ip, geo_reader, asn_reader):
    metadata = {}
    try:
        # Usamos la base de datos de CITY (que incluye país)
        geo_res = geo_reader.city(ip)
        
        metadata.update({
            # CAMPOS ESTÁNDAR (Para que Neo4j cree relaciones automáticas)
            "city": geo_res.city.name,
            "country": geo_res.country.name,
            "country_code": geo_res.country.iso_code, # Vital para _materialize_country_nodes
            
            # CAMPOS ADICIONALES (Se guardan como propiedades del nodo IP)
            "x_latitude": geo_res.location.latitude,
            "x_longitude": geo_res.location.longitude,
            "x_region": geo_res.subdivisions.most_specific.name,
            "x_postal_code": geo_res.postal.code,
            "x_timezone": geo_res.location.time_zone
        })
    except Exception:
        pass

    try:
        # Usamos la base de datos de ASN
        asn_res = asn_reader.asn(ip)
        metadata.update({
            "asn": asn_res.autonomous_system_number, # Vital para _materialize_asn_nodes
            "x_as_organization": asn_res.autonomous_system_organization,
        })
    except Exception:
        pass

    return {k: v for k, v in metadata.items() if v is not None}
    
def create_stix_objects(
    ip_addresses,
    threatview_identity,
    threatview_marking,
    script_run_time,
    geo_reader,
    asn_reader,
):
    """Crea objetos STIX y devuelve cuántos han sido enriquecidos."""
    stix_objects = []
    enriched_count = 0
    
    threatview_marking_id = threatview_marking["id"]
    threatview_identity_id = threatview_identity["id"]

    for ip in ip_addresses:
        # Usamos la función local integrada
        geo_metadata = get_local_enrichment(ip, geo_reader, asn_reader)
        
        if geo_metadata:
            enriched_count += 1

        ipv4_obj = IPv4Address(
            value=ip,
            custom_properties=geo_metadata,
            allow_custom=True,
        )

        indicator_name = f"IPv4: {ip}"
        indicator_id = generate_uuid5(indicator_name, namespace=threatview_marking_id)
        indicator_id_full = f"indicator--{indicator_id}"

        indicator = Indicator(
            id=indicator_id_full,
            created_by_ref=threatview_identity_id,
            created=script_run_time,
            modified=script_run_time,
            valid_from=script_run_time,
            indicator_types=["malicious-activity"],
            name=indicator_name,
            pattern=f"[ipv4-addr:value='{ip}']",
            pattern_type="stix",
            object_marking_refs=[
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                threatview_marking_id,
            ],
        )

        stix_objects.append(ipv4_obj)
        stix_objects.append(indicator)
        
        relationship = make_relationship(
            source_ref=indicator["id"],
            target_ref=ipv4_obj["id"],
            relationship_type="indicates",
            created_by_ref=threatview_identity_id,
            marking_refs=indicator["object_marking_refs"],
            created=script_run_time,
        )
        stix_objects.append(relationship)

    return stix_objects, enriched_count

def main():
    parser = argparse.ArgumentParser(description="ThreatView to STIX 2.1 - Local Enrichment")
    args = parser.parse_args()

    # Verificar existencia de DBs antes de empezar
    if not os.path.exists(GEO_DB_PATH) or not os.path.exists(ASN_DB_PATH):
        logger.error(f"Faltan bases de datos locales ({GEO_DB_PATH} o {ASN_DB_PATH}).")
        return 1

    try:
        output_dir, _ = setup_output_directory(BASE_OUTPUT_DIR, clean=True)
        script_run_time = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        feeds2stix_marking = fetch_external_objects()

        threatview_identity = create_threatview_identity()
        threatview_marking = create_threatview_marking_definition()

        ip_addresses = fetch_threatview_feed()
        total_ips = len(ip_addresses)
        total_enriched = 0
        stix_objects = []
        checkpoint_filename = f"threatview_ip_{datetime.now(UTC).strftime('%Y%m%d')}"

        # ABRIMOS LOS LECTORES UNA SOLA VEZ (Eficiencia máxima)
        with geoip2.database.Reader(GEO_DB_PATH) as geo_reader, \
             geoip2.database.Reader(ASN_DB_PATH) as asn_reader:

            for start_idx in range(0, total_ips, CHECKPOINT_SIZE):
                chunk = ip_addresses[start_idx : start_idx + CHECKPOINT_SIZE]
                
                chunk_stix, count = create_stix_objects(
                    chunk,
                    threatview_identity,
                    threatview_marking,
                    script_run_time,
                    geo_reader,
                    asn_reader
                )
                
                stix_objects.extend(chunk_stix)
                total_enriched += count

                bundle = create_bundle_with_metadata(
                    stix_objects,
                    threatview_identity,
                    threatview_marking,
                    feeds2stix_marking,
                )

                bundle_path = save_bundle_to_file(bundle, output_dir, checkpoint_filename, add_timestamp=False)
                
                processed = min(start_idx + CHECKPOINT_SIZE, total_ips)
                logger.info(f"Progress: {processed}/{total_ips} IPs processed...")

        # --- RESUMEN FINAL POR PANTALLA ---
        print("\n" + "="*50)
        print(f"RESUMEN DE PROCESAMIENTO")
        print("-" * 50)
        print(f"Total IPs descargadas:      {total_ips}")
        print(f"IPs correlacionadas (Geo):  {total_enriched}")
        print(f"Tasa de éxito:              {(total_enriched/total_ips)*100:.2f}%")
        print(f"Bundle STIX guardado en:    {bundle_path}")
        print("="*50 + "\n")

        return 0

    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        return 1

if __name__ == "__main__":
    exit(main())