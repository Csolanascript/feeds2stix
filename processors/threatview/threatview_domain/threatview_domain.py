import argparse
import json
import logging
import os
import socket
import uuid
import geoip2.database
from datetime import UTC, datetime

import requests
from stix2 import DomainName, Indicator

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

THREATVIEW_DOMAIN_FEED_URL = "https://threatview.io/Downloads/DOMAIN-High-Confidence-Feed.txt"
BASE_OUTPUT_DIR = "outputs/threatview_domain"
CHECKPOINT_FILENAME = "threatview_domain_enriched"
CHECKPOINT_SIZE = 1000

GEO_DB_PATH = "GeoLite2-City.mmdb"
ASN_DB_PATH = "GeoLite2-ASN.mmdb"

# --- FUNCIONES DE IDENTIDAD (Añadidas de nuevo) ---

def create_threatview_identity():
    """Create the ThreatView identity object"""
    return create_identity_object(
        name="ThreatView",
        description="Verified threat feeds for domains.",
        identity_class="organization",
        contact_info="https://threatview.io/",
    )

def create_threatview_marking_definition():
    """Create a marking definition for ThreatView feed"""
    return create_marking_definition_object(f"Origin: {THREATVIEW_DOMAIN_FEED_URL}")

def fetch_threatview_feed():
    """Fetch domains from ThreatView feed"""
    logger.info(f"Fetching ThreatView Domain feed...")
    response = requests.get(THREATVIEW_DOMAIN_FEED_URL)
    response.raise_for_status()
    domains = [
        line.strip()
        for line in response.text.splitlines()
        if line.strip() and not line.startswith("#")
    ]
    logger.info(f"Found {len(domains)} domains in feed")
    return domains

# --- LÓGICA DE PERSISTENCIA Y ENRIQUECIMIENTO ---

def load_existing_progress(output_dir):
    """Lee el archivo JSON actual si existe y extrae los dominios ya procesados."""
    file_path = os.path.join(output_dir, "bundles", f"{CHECKPOINT_FILENAME}.json")
    if not os.path.exists(file_path):
        logger.info("No se encontró progreso previo. Empezando desde cero.")
        return [], set()

    try:
        with open(file_path, "r") as f:
            data = json.load(f)
            all_objs = data.get("objects", [])
            already_done = {obj["value"] for obj in all_objs if obj["type"] == "domain-name"}
            core_objs = [obj for obj in all_objs if obj["type"] not in ("identity", "marking-definition")]
            logger.info(f"💾 Progreso cargado: {len(already_done)} dominios ya en el archivo.")
            return core_objs, already_done
    except Exception as e:
        logger.error(f"Error al cargar el archivo existente: {e}")
        return [], set()

def get_domain_enrichment(domain, geo_reader, asn_reader):
    metadata = {}
    try:
        resolved_ip = socket.gethostbyname(domain)
        metadata["x_resolved_ip"] = resolved_ip
        try:
            geo_res = geo_reader.city(resolved_ip)
            metadata.update({
                "city": geo_res.city.name,
                "country": geo_res.country.name,
                "country_code": geo_res.country.iso_code,
                "x_latitude": geo_res.location.latitude,
                "x_longitude": geo_res.location.longitude,
            })
        except: pass
        try:
            asn_res = asn_reader.asn(resolved_ip)
            metadata.update({
                "asn": asn_res.autonomous_system_number,
                "x_as_organization": asn_res.autonomous_system_organization,
            })
        except: pass
    except:
        metadata["x_status"] = "inactive_or_nxdomain"
    return {k: v for k, v in metadata.items() if v is not None}

def create_stix_objects(domains, threatview_identity, threatview_marking, script_run_time, geo_reader, asn_reader, processed_set):
    stix_objects = []
    enriched_count = 0
    skipped_count = 0
    
    for domain in domains:
        if domain in processed_set:
            skipped_count += 1
            continue
        
        processed_set.add(domain)
        metadata = get_domain_enrichment(domain, geo_reader, asn_reader)
        if "country_code" in metadata:
            enriched_count += 1

        domain_obj = DomainName(value=domain, custom_properties=metadata, allow_custom=True)
        indicator_id = f"indicator--{generate_uuid5(f'Domain: {domain}', namespace=threatview_marking['id'])}"
        
        indicator = Indicator(
            id=indicator_id,
            created_by_ref=threatview_identity["id"],
            created=script_run_time,
            modified=script_run_time,
            valid_from=script_run_time,
            indicator_types=["malicious-activity"],
            name=f"Domain: {domain}",
            pattern=f"[domain-name:value='{domain}']",
            pattern_type="stix",
            object_marking_refs=["marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487", threatview_marking["id"]],
        )

        stix_objects.extend([domain_obj, indicator])
        stix_objects.append(make_relationship(
            source_ref=indicator.id, target_ref=domain_obj.id,
            relationship_type="indicates", created_by_ref=threatview_identity["id"],
            marking_refs=indicator.object_marking_refs, created=script_run_time
        ))

    return stix_objects, enriched_count, skipped_count

def main():
    if not os.path.exists(GEO_DB_PATH) or not os.path.exists(ASN_DB_PATH):
        logger.error("Bases de datos locales no encontradas (.mmdb).")
        return 1

    try:
        output_dir, _ = setup_output_directory(BASE_OUTPUT_DIR, clean=False)
        all_stix, processed_domains = load_existing_progress(output_dir)
        
        script_run_time = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        feeds2stix_marking = fetch_external_objects()
        threatview_identity = create_threatview_identity()
        threatview_marking = create_threatview_marking_definition()

        domains_in_feed = fetch_threatview_feed()
        total_in_feed = len(domains_in_feed)
        
        total_enriched_today = 0
        total_skipped = 0

        logger.info(f"Procesando {total_in_feed} dominios...")

        with geoip2.database.Reader(GEO_DB_PATH) as geo_reader, \
             geoip2.database.Reader(ASN_DB_PATH) as asn_reader:

            for i in range(0, total_in_feed, CHECKPOINT_SIZE):
                chunk = domains_in_feed[i : i + CHECKPOINT_SIZE]
                
                new_objs, enriched, skipped = create_stix_objects(
                    chunk, threatview_identity, threatview_marking, 
                    script_run_time, geo_reader, asn_reader, processed_domains
                )
                
                if new_objs:
                    all_stix.extend(new_objs)
                    total_enriched_today += enriched
                    bundle = create_bundle_with_metadata(all_stix, threatview_identity, threatview_marking, feeds2stix_marking)
                    save_bundle_to_file(bundle, output_dir, CHECKPOINT_FILENAME, add_timestamp=False)
                
                total_skipped += skipped
                logger.info(f"Progreso: {min(i + CHECKPOINT_SIZE, total_in_feed)}/{total_in_feed} | Saltados (Ya hechos): {total_skipped}")

        print("\n" + "═"*50)
        print(f"📊 RESUMEN FINAL")
        print("─" * 50)
        print(f"Dominios en feed:          {total_in_feed}")
        print(f"Saltados (Ya en archivo):  {total_skipped}")
        print(f"Nuevos hoy:                {total_enriched_today}")
        print(f"Total en Bundle STIX:      {len(all_stix)}")
        print("═"*50 + "\n")

        return 0
    except Exception as e:
        logger.error(f"Fallo crítico: {e}", exc_info=True)
        return 1

if __name__ == "__main__":
    exit(main())