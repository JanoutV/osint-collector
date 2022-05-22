#!/usr/bin/env python
# Author: xjanou19@vut.cz
# Description: CLI tool to query OSINT for IoCs
# Make sure you have a file named config.ini in the osint_collector folder
# provide your API keys in the config.ini file
# AVT -> AlienVault OTX API key
# VT -> VirusTotal API key
# ABUSE -> AbuseIPDB API key
from OTXv2 import OTXv2
import IndicatorTypes
import argparse
from config import Config
from rich.console import Console
from itertools import islice
import requests
import json
import pprint
# from rich import print_json
# import traceback



def delimiter():
    print("=======================================")


def fetch_data_from_url(url, service_name, headers=None, decode=True, params=None):
    """
    Function for downloading data from a specific URL
    :param url: URL to be fetched
    :param headers: Headers to be used for the request
    :param decode: True if the data should be decoded
    :param params: Additional parameters to be supplied with the request
    :return: The queried data either unaltered or decoded, or None if
             nothing was fetched
    """
    # If the URL is empty or None, return None
    if not url:
        print("Missing URL, cannot fetch data")
        return None
    # Timeout - TBD
    # Fetch the data using Requests library
    try:
        session = requests.session()
        response = session.get(url, headers=headers, params=params)
    except Exception as e:
        print(f"Failed to retrieve data from {url}, exception: {repr(e)}")
        return None
    # Don't decode if the decode param is set to False
    if not decode:
        return response.content
    # Otherwise first try to decode as UTF-8 and if it doesn't work, then
    # decode as ASCII
    try:
        content = response.content.decode("utf-8")
    except UnicodeDecodeError:
        try:
            content = response.content.decode("ascii")
        except Exception:
            return response.content

    return content


def main():
    parser = argparse.ArgumentParser(
        description="OSINT Collector",
        add_help=True,
        epilog="OSINT Collector, Written by Vladimir Janout, 2022, xjanou19@vut.cz",
    )
    parser.add_argument(
        "-d", "--domain", help="Domain, for example: vut.cz", required=False
    )
    parser.add_argument(
        "-a",
        "--all",
        help="Get unfiltered, unformated output from the API's.",
        required=False,
        action="store_true",
    )
    parser.add_argument("-i", "--ip", help="IPv4 eg: 8.8.8.8", required=False)
    parser.add_argument("-u", "--url", help="URL eg; http://www.vut.cz", required=False)
    parser.add_argument(
        "-H",
        "--hash",
        help="Hash of a file, MD5, SHA256, etc.",
        required=False,
    )
    parser.add_argument(
        "-p",
        "--pulse",
        help="Search OTX pulses for a string eg: Dridex",
        required=False,
    )
    parser.add_argument(
        "-s",
        "--subscribed",
        help="Get Alien Vault pulses you are subscribed to",
        required=False,
        action="store_true",
    )

    args = vars(parser.parse_args())

    try:
        otx_token = Config.get_value_from_conf("AVT")
        vt_token = Config.get_value_from_conf("VT")
        # limit for abuse is 1000 requests PER DAY for the standard user.
        abuse_token = Config.get_value_from_conf("ABUSE")
    except Exception:
        raise AttributeError("Error getting config attributes.")
    # create the enhanced Console object
    console = Console()
    # -------API OBJECT ESTABLISHMENT----------
    otx = OTXv2(otx_token)
    virus_total_url_v3 = "https://www.virustotal.com/api/v3/{}/{}"
    vt_relationship_url = "https://www.virustotal.com/api/v3/{}/{}/{}"
    vt_headers = {"Accept": "application/json", "x-apikey": f"{vt_token}"}
    abuse_url = "https://api.abuseipdb.com/api/v2/check"
    abuse_headers = {"Accept": "application/json", "Key": f"{abuse_token}"}

    abuse_categories = {
        "1": "DNS Compromise",
        "2": "DNS Poisoning",
        "3": "Fraud Orders",
        "4": "DDoS Attack",
        "5": "FTP Brute-Force",
        "6": "Ping of Death",
        "7": "Phishing",
        "8": "Fraud VoIP",
        "9": "Open Proxy",
        "10": "Web Spam",
        "11": "Email Spam",
        "12": "Blog Spam",
        "13": "VPN IP",
        "14": "Port Scan",
        "15": "Hacking",
        "16": "SQL Injection",
        "17": "Spoofing",
        "18": "Brute-Force",
        "19": "Bad Web Bot",
        "20": "Exploited Host",
        "21": "Web App Attack",
        "22": "SSH",
        "23": "IoT Targeted",
    }
    if args["ip"]:
        # -------ALIEN VAULT----------
        with console.status(
            f"[bold green] Fetching OSINT from Alien Vault for {args['ip']}..."
        ):
            try:
                otx_data = otx.get_indicator_details_full(
                    IndicatorTypes.IPv4, args["ip"]
                )
            except Exception as e:
                print(e)
                if "IP is private" in str(e):
                    print("You cannot scan an IP address from the private IP range")
                    return None
            print("#ALIENVAULT OSINT")
            delimiter()
            # If the all option is toggled, just print out
            if args["all"]:
                pprint.pprint(otx_data)
            else:
                # we use the get method here to treat dict values gracefully
                # 1. GENERAL subdict
                otx_data_general = otx_data["general"]
                print("GENERAL:")
                print(f"ASN: {otx_data_general.get('asn')}")
                print(f"Country name: {otx_data_general.get('country_name')}")
                delimiter()
                pulses = otx_data_general["pulse_info"].get("pulses")
                print(
                    f"Number of pulses: {otx_data_general['pulse_info'].get('count')}"
                )
                delimiter()
                print("PULSE INFO (max 10 pulses):")
                for pulse in islice(pulses, 10):
                    print(f"Name of Pulse: {pulse.get('name')}")
                    print(f"Pulse ID: {pulse.get('id')}")
                    print(f"Adversary connected: {pulse.get('adversary')}")
                    print(f"Attack IDs: {pulse.get('attack_ids')}")
                    print(f"Description: {pulse.get('description')}")
                    print(f"Tags: {pulse.get('tags')}")
                    print(f"Targetted Countries: {pulse.get('targeted_countries')}")
                    print(
                        f"Connected Malware families: {pulse.get('malware_families')}"
                    )
                    delimiter()

                # 2. URL_LIST subdict
                delimiter()
                print("CONNECTED URL INFO:")
                otx_data_url = otx_data["url_list"]
                print(f"Number of connected URL's: {otx_data_url.get('full_size')}")
                urls = otx_data_url["url_list"]
                for url in urls:
                    print(f"URL: {url.get('url')}")
                    print(f"Date of submission: {url.get('date')}")
                    delimiter()

        # -------VIRUSTOTAL----------
        with console.status(
            f"[bold green] Fetching OSINT IP report from Virus Total for {args['ip']}..."
        ):
            # VT IP ADDRESS REPORT
            # AS PER https://developers.virustotal.com/reference/ip-info
            try:
                url = virus_total_url_v3.format("ip_addresses", args["ip"])
                queried_data = fetch_data_from_url(
                    url, "virustotal", headers=vt_headers
                )
            except Exception as e:
                print(e)
            if not queried_data:
                print(f"No data found for {args['ip']} by VirusTotal.")
                return None
            json_data = json.loads(queried_data)

            if args["all"]:
                print("#VIRUSTOTAL ALL OSINT")
                pprint.pprint(json_data)
            else:
                print("#VIRUSTOTAL OSINT")
                delimiter()
                vt_data_analysis_results = json_data["data"]["attributes"][
                    "last_analysis_results"
                ]
                vt_data_analysis_stats = json_data["data"]["attributes"][
                    "last_analysis_stats"
                ]
                print(
                    f"Last analysis results - Number of engines that marked the indicator:"
                )
                print(f"harmless: {vt_data_analysis_stats['harmless']}")
                print(f"malicious: {vt_data_analysis_stats['malicious']}")
                print(f"suspicious: {vt_data_analysis_stats['suspicious']}")
                print(f"undetected: {vt_data_analysis_stats['undetected']}")
                print(f"timeout: {vt_data_analysis_stats['timeout']}")
                delimiter()
                print(
                    "List of engines that marked the indicator as malicious/suspicious:"
                )
                for engine in vt_data_analysis_results:
                    if vt_data_analysis_results[engine]["result"] == (
                        "malicious" or "suspicious"
                    ):
                        print(
                            f"{vt_data_analysis_results[engine]['engine_name']} -> {vt_data_analysis_results[engine]['result']}"
                        )
                delimiter()

            # VT IP RELATIONSHIPS - 1. URLS(enteprise feature), 2. REFERRER_FILES,
            # 3. COMMUNICATING_FILES

            ## REFERRER FILES
            # try:
            #     url = vt_relationship_url.format(
            #         "ip_addresses", args["ip"], "referrer_files?limit=10"
            #     )
            #     queried_data = fetch_data_from_url(
            #         url, "virustotal", headers=vt_headers
            #     )
            # except Exception as e:
            #     print(e)
            # if not queried_data:
            #     print(f"No data found for {args['ip']} by VirusTotal.")
            #     return None
            # json_data = json.loads(queried_data)
            # print("#VIRUSTOTAL OSINT - REFERRER FILES")
            # pprint.pprint(json_data)
            ## 2. COMMUNICATING FILES
            try:
                url = vt_relationship_url.format(
                    "ip_addresses", args["ip"], "communicating_files?limit=10"
                )
                queried_data = fetch_data_from_url(
                    url, "virustotal", headers=vt_headers
                )
            except Exception as e:
                print(e)
            if not queried_data:
                print(f"No data found for {args['ip']} by VirusTotal.")
                return None
            json_data = json.loads(queried_data)
            if args["all"]:
                print("#VIRUSTOTAL OSINT - COMMUNICATING FILES")
                # pprint.pprint(json_data)

            ## 3. URL's -> Enterprise feature
            try:
                url = vt_relationship_url.format(
                    "ip_addresses", args["ip"], "urls?limit=10"
                )
                queried_data = fetch_data_from_url(
                    url, "virustotal", headers=vt_headers
                )
            except Exception as e:
                print(e)
            if not queried_data:
                print(f"No data found for {args['ip']} by VirusTotal.")
                return None
            json_data = json.loads(queried_data)

            if args["all"]:
                print("#VIRUSTOTAL OSINT - URL's")
                pprint.pprint(json_data)

        # -------AbuseIPDB----------
        with console.status(
            f"[bold green] Fetching OSINT IP report from AbuseIPDB for {args['ip']}..."
        ):
            # AbuseIPDB report
            # AS PER https://docs.abuseipdb.com/?python#check-endpoint
            try:
                querystring = {
                    "ipAddress": f"{args['ip']}",
                    "maxAgeInDays": "90",
                    "verbose": "",
                }
                queried_data = fetch_data_from_url(
                    abuse_url, "AbuseIPDB", headers=abuse_headers, params=querystring
                )
            except Exception as e:
                print(e)
            if not queried_data:
                print(f"No data found for {args['ip']} by AbuseIPDB.")
                return None
            json_data = json.loads(queried_data)

            if args["all"]:
                print("#ABUSEIPDB ALL OSINT")
                pprint.pprint(json_data)
            else:
                print("#AbuseIPDB OSINT")
                delimiter()
                abuse_reports = json_data["data"].get("reports")
                del json_data["data"]["reports"]
                print(json.dumps(json_data, sort_keys=True, indent=4))
                # pprint.pprint(json_data)
                delimiter()
                print("ABUSE IPDB 10 LATEST REPORTS:")
                delimiter()
                ##PRINT TOP 10 latest reports
                for report in islice(abuse_reports, 10):
                    print(json.dumps(report, sort_keys=True, indent=4))
                    delimiter()

    if args["domain"]:
        with console.status(
            f"[bold green] Fetching OSINT from Alien Vault for {args['domain']}..."
        ):
            try:
                otx_data = otx.get_indicator_details_full(
                    IndicatorTypes.DOMAIN, args["domain"]
                )
            except Exception as e:
                print(e)
                return None
            pprint.pprint(otx_data)

    # if args["hostname"]:
    #     with console.status(
    #         f"[bold green] Fetching OSINT from Alien Vault for {args['hostname']}..."
    #     ):
    #         try:
    #             otx_data = otx.get_indicator_details_full(
    #                 IndicatorTypes.HOSTNAME, args["hostname"]
    #             )
    #         except Exception as e:
    #             print(e)
    #             return None
    #         pprint.pprint(otx_data)

    if args["url"]:
        with console.status(
            f"[bold green] Fetching OSINT from Alien Vault for {args['url']}..."
        ):
            try:
                otx_data = otx.get_indicator_details_full(
                    IndicatorTypes.URL, args["url"]
                )
            except Exception as e:
                print(e)
                return None
            pprint.pprint(otx_data)

    if args["hash"]:
        with console.status(
            f"[bold green] Fetching OSINT from Alien Vault for {args['hash']}..."
        ):
            try:
                otx_data = otx.get_indicator_details_full(
                    IndicatorTypes.FILE_HASH_MD5, args["hash"]
                )
            except Exception as e:
                print(e)
                return None
            if args["all"]:
                pprint.pprint(otx_data)
            else:
                ...
                print("OTX OSINT:")
                # 1. General subdict with Pulse info
                delimiter()
                otx_data_general = otx_data.get("general", {})
                print("PULSE INFO:")
                pulses = otx_data_general.get("pulse_info", {}).get("pulses", {})
                print(
                    f"Number of pulses: {otx_data_general['pulse_info'].get('count')}"
                )
                for pulse in pulses:
                    print(f"Name of Pulse: {pulse.get('name')}")
                    print(f"Pulse ID: {pulse.get('id')}")
                    print(f"Adversary connected: {pulse.get('adversary')}")
                    print(f"Attack IDs: {pulse.get('attack_ids')}")
                    print(f"Description: {pulse.get('description')}")
                    print(f"Tags: {pulse.get('tags')}")
                    print(f"Targetted Countries: {pulse.get('targeted_countries')}")
                    print(
                        f"Connected Malware families: {pulse.get('malware_families')}"
                    )
                    delimiter()

        # VT IP FILE REPORT
        # AS PER https://developers.virustotal.com/reference/file-info
        with console.status(
            f"[bold green] Fetching OSINT FILE report from Virus Total for {args['hash']}..."
        ):
            try:
                url = virus_total_url_v3.format("files", args["hash"])
                queried_data = fetch_data_from_url(
                    url, "virustotal", headers=vt_headers
                )
            except Exception as e:
                print(e)
            if not queried_data:
                print(f"No data found for {args['hash']} by VirusTotal.")
                return None
            json_data = json.loads(queried_data)

            if args["all"]:
                print("#VIRUSTOTAL ALL OSINT")
                pprint.pprint(json_data)
            else:
                print("#VIRUSTOTAL OSINT")
                delimiter()
                vt_data_analysis_results = json_data["data"]["attributes"][
                    "last_analysis_results"
                ]
                vt_data_analysis_stats = json_data["data"]["attributes"][
                    "last_analysis_stats"
                ]
                vt_data_exiftool = (
                    json_data.get("data", {}).get("attributes", {}).get("exiftool", {})
                )
                vt_data_classification = (
                    json_data.get("data", {})
                    .get("attributes", {})
                    .get("popular_threat_classification", {})
                )
                print("File Metadata:")
                print(f"CPU architecture: {vt_data_exiftool.get('CPUArchitecture')}")
                print(f"File Type: {vt_data_exiftool.get('FileType')}")
                print(f"CPU Byte Order: {vt_data_exiftool.get('CPUByteOrder')}")
                print(
                    f"Suggested VT label: {vt_data_classification.get('suggested_threat_label')}"
                )
                delimiter()
                print(
                    f"Last analysis results - Number of engines that marked the indicator:"
                )
                print(f"harmless: {vt_data_analysis_stats['harmless']}")
                print(f"malicious: {vt_data_analysis_stats['malicious']}")
                print(f"suspicious: {vt_data_analysis_stats['suspicious']}")
                print(f"undetected: {vt_data_analysis_stats['undetected']}")
                print(f"timeout: {vt_data_analysis_stats['timeout']}")
                delimiter()
                print(
                    "List of engines that marked the indicator as malicious/suspicious:"
                )
                delimiter()
                for engine in vt_data_analysis_results:
                    if vt_data_analysis_results[engine]["category"] == (
                        "malicious" or "suspicious"
                    ):
                        print(
                            f"{vt_data_analysis_results[engine]['engine_name']} -> {vt_data_analysis_results[engine]['result']}"
                        )
                delimiter()

    if args["pulse"]:
        with console.status(
            f"[bold green] Fetching OSINT from Alien Vault for {args['pulse']}..."
        ):
            try:
                result = otx.search_pulses(args["pulse"])
            except Exception as e:
                repr(print(e))
                return None
            pprint.pprint(result.get("results"))

    if args["subscribed"]:
        print(str(otx.getall(max_items=3, limit=5)))


if __name__ == "__main__":
    main()
