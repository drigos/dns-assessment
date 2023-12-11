import argparse
import contextlib
import csv
import io
import json
import os
import re
import socket
import sys
from collections import defaultdict

import dns.resolver
import requests
import tldextract
import whois
from dotenv import load_dotenv
from lxml import etree
from tqdm import tqdm

load_dotenv()

resolver = dns.resolver.Resolver()
resolver.nameservers = [os.getenv("DNS_NAMESERVER")]


def subdomain_check(domain):
    subdomain = False

    try:
        tld = tldextract.extract(domain)
        if tld.subdomain:
            subdomain = True
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)

    return subdomain


def authoritative_check(domain):
    is_authoritative = False

    try:
        ns_records = resolver.resolve(domain, "NS")
        if ns_records:
            is_authoritative = True
    except dns.resolver.NoAnswer:
        # The DNS response does not contain an answer to the question
        pass
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)

    return is_authoritative


def dnssec_check(domain):
    has_dnssec = False

    try:
        dnskey_records = resolver.resolve(domain, "DNSKEY")
        if dnskey_records:
            has_dnssec = True
    except dns.resolver.NoAnswer:
        # The DNS response does not contain an answer to the question
        pass
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)

    return has_dnssec


def get_registrar(domain):
    registrar = ""

    try:
        with open(os.devnull, "w") as devnull:
            with contextlib.redirect_stdout(devnull):
                domain_info = whois.whois(domain)
        if domain_info.registrar:
            registrar = domain_info.get("registrar", "")
        elif domain.endswith(".br"):
            registrar = "Registro.br"
            match = re.search(r"owner-c:\s*(\w+)", domain_info.text)
            if match:
                registrar += f" ({match.group(1)})"
        else:
            match = re.search(
                r"Registrar:\s*(.+)", domain_info.text, re.IGNORECASE
            )
            if match:
                return match.group(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)

    return registrar


def get_zone_provider(domain):
    zone_provider = ""

    try:
        ns_records = resolver.resolve(domain, "NS")
        ns_record = str(ns_records[0])
        ns_ip = socket.gethostbyname(ns_record)
        zone_provider_info = requests.get(
            f'https://ipinfo.io/{ns_ip}/json?token={os.getenv("IPINFO_TOKEN")}'
        ).json()
        org_name = zone_provider_info.get("org", "")
        zone_provider = re.sub(r"AS\d+\s", "", org_name)
    except dns.resolver.NoAnswer:
        # The DNS response does not contain an answer to the question
        pass
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)

    return zone_provider


def get_dmarc_info(domain):
    dmarc_record = ""
    dmarc_policy = ""

    try:
        txt_records = resolver.resolve(f"_dmarc.{domain}", "TXT")

        for txt_record in txt_records:
            sanitized_record = txt_record.to_text().strip('"')
            if sanitized_record.startswith("v=DMARC1"):
                dmarc_record = sanitized_record
                dmarc_info = sanitized_record.split(";")
                for item in dmarc_info:
                    if item.strip().startswith("p="):
                        dmarc_policy = item.strip().split("=")[1]
                        break
    except dns.resolver.NoAnswer:
        # The DNS response does not contain an answer to the question
        pass
    except dns.resolver.NXDOMAIN:
        # The DNS query name does not exist
        pass
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)

    return {
        "dmarc_record": dmarc_record,
        "dmarc_policy": dmarc_policy,
    }


def get_spf_info(domain):
    spf_record = ""
    spf_action = ""

    try:
        txt_records = resolver.resolve(domain, "TXT")

        for txt_record in txt_records:
            sanitized_record = txt_record.to_text().strip('"')
            if sanitized_record.startswith("v=spf1"):
                spf_record = sanitized_record
                spf_info = sanitized_record.split(" ")
                spf_action = spf_info[-1]
                break
    except dns.resolver.NoAnswer:
        # The DNS response does not contain an answer to the question
        pass
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)

    return {
        "spf_record": spf_record,
        "spf_action": spf_action,
    }


def get_bimi_info(domain):
    bimi_record = ""
    bimi_location = ""
    bimi_logo_valid = False

    try:
        txt_records = resolver.resolve(f"default._bimi.{domain}", "TXT")

        for txt_record in txt_records:
            sanitized_record = txt_record.to_text().strip('"')
            if sanitized_record.startswith("v=BIMI1"):
                bimi_record = sanitized_record
                bimi_info = sanitized_record.split(";")
                for item in bimi_info:
                    if item.strip().startswith("l="):
                        bimi_location = item.strip().split("=")[1]
                        break

        if bimi_location:
            bimi_logo_valid = validate_bimi_image(
                bimi_location, os.getenv("BIMI_RNG_SCHEMA_PATH")
            )
    except dns.resolver.NoAnswer:
        # The DNS response does not contain an answer to the question
        pass
    except dns.resolver.NXDOMAIN:
        # The DNS query name does not exist
        pass
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)

    return {
        "bimi_record": bimi_record,
        "bimi_location": bimi_location,
        "bimi_logo_valid": bimi_logo_valid,
    }


def validate_bimi_image(bimi_location, rng_schema_path):
    # Download BIMI image
    response = requests.get(bimi_location)
    bimi_image = response.content

    # Load RelaxNG schema
    with open(rng_schema_path, "r") as file:
        rng_schema = etree.RelaxNG(etree.parse(file))

    # Parse BIMI image as XML
    bimi_xml = etree.fromstring(bimi_image)

    # Validate BIMI image against schema
    is_valid = rng_schema.validate(bimi_xml)

    return is_valid


def get_dns_info(domain):
    is_subdomain = subdomain_check(domain)
    is_authoritative = authoritative_check(domain)
    registrar = get_registrar(domain)

    has_dnssec = False
    zone_provider = ""
    dmarc_info = defaultdict(str)
    spf_info = defaultdict(str)
    bimi_info = defaultdict(str)
    if is_authoritative:
        has_dnssec = dnssec_check(domain)
        zone_provider = get_zone_provider(domain)
        dmarc_info = get_dmarc_info(domain)
        spf_info = get_spf_info(domain)
        bimi_info = get_bimi_info(domain)

    return {
        "domain": domain,
        "is_subdomain": is_subdomain,
        "is_authoritative": is_authoritative,
        "has_dnssec": has_dnssec,
        "registrar": registrar,
        "zone_provider": zone_provider,
        "dmarc_record": dmarc_info["dmarc_record"],
        "dmarc_policy": dmarc_info["dmarc_policy"],
        "spf_record": spf_info["spf_record"],
        "spf_action": spf_info["spf_action"],
        "bimi_record": bimi_info["bimi_record"],
        "bimi_location": bimi_info["bimi_location"],
        "bimi_logo_valid": bimi_info["bimi_logo_valid"],
    }


def process_domains(file_path):
    with open(file_path, "r") as file:
        domains = [line.strip() for line in file if not line.startswith("#")]

    results = []
    for domain in tqdm(domains, desc="Processing domains"):
        dns_info = get_dns_info(domain)
        results.append(dns_info)

    return results


def results_to_csv(results):
    output = io.StringIO()
    keys = results[0].keys()
    writer = csv.DictWriter(output, fieldnames=keys)
    writer.writeheader()
    writer.writerows(results)
    return output.getvalue()


def results_to_json(results):
    return json.dumps(results, indent=4)


def main():
    parser = argparse.ArgumentParser(description="DNS Assessment")
    parser.add_argument(
        "file_path", help="File path containing domains to be assessed"
    )
    parser.add_argument(
        "--output",
        default="json",
        choices=["json", "csv"],
        help="Output format",
    )
    args = parser.parse_args()

    domains_info = process_domains(args.file_path)
    if args.output == "csv":
        output = results_to_csv(domains_info)
    else:
        output = results_to_json(domains_info)
    print(output)


if __name__ == "__main__":
    main()
