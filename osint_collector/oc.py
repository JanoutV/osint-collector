from OTXv2 import OTXv2
import IndicatorTypes
import argparse
from config import Config
from rich.console import Console
from rich import print_json
import pandas as pd
import pprint

# import traceback
import vt
import requests
import json


def fetch_data_from_url(url, service_name, headers=None, decode=True, usetor=False):
    """
    Function for downloading data from a specific URL
    :param url: URL to be fetched
    :param headers: Headers to be used for the request
    :param decode: True if the data should be decoded
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
        response = session.get(url, headers=headers)
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
        description="OSINT querry tool",
        add_help=True,
        epilog="OSINT Collector, Written by Vladimir Janout, 2022",
    )
    parser.add_argument(
        "-d", "--domain", help="Domain, for example: vut.cz", required=False
    )
    parser.add_argument(
        "-b",
        "--brief",
        help="Get only the most important enrichment for given indicator",
        required=False,
    )
    parser.add_argument("-i", "--ip", help="IPv4 eg: 8.8.8.8", required=False)
    parser.add_argument(
        "-ho", "--hostname", help="Hostname eg: www.vut.cz", required=False
    )
    parser.add_argument("-u", "--url", help="URL eg; http://www.vut.cz", required=False)
    parser.add_argument(
        "-m",
        "--md5",
        help="MD5 Hash of a file eg; 7b42b35832855ab4ff37ae9b8fa9e571",
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
    except Exception:
        raise AttributeError("Error getting config attributes.")
    # create the enhanced Console object
    console = Console()
    # -------API OBJECT ESTABLISHMENT----------
    # OTX
    otx = OTXv2(otx_token)
    # VT
    vt_client = vt.Client(vt_token)
    # virus_total_url_v2 = "https://www.virustotal.com/vtapi/v2/{}/report?{}={}&apikey={}"
    virus_total_url_v3 = "https://www.virustotal.com/api/v3/{}/{}"
    vt_relationship_url = "https://www.virustotal.com/api/v3/{}/{}/{}"
    vt_headers = {"Accept": "application/json", "x-apikey": f"{vt_token}"}
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
            pprint.pprint(otx_data)

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
            print("#VIRUSTOTAL OSINT")
            pprint.pprint(json_data)

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
            print("#VIRUSTOTAL OSINT - URL's")
            # pprint.pprint(json_data)

        # -------X-FORCE EXCHANGE----------
        #   with console.status(
        #     f"[bold green] Fetching OSINT from IBM X-FORCE for {args['ip']}..."
        # ): try:

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

    if args["hostname"]:
        with console.status(
            f"[bold green] Fetching OSINT from Alien Vault for {args['hostname']}..."
        ):
            try:
                otx_data = otx.get_indicator_details_full(
                    IndicatorTypes.HOSTNAME, args["hostname"]
                )
            except Exception as e:
                print(e)
                return None
            pprint.pprint(otx_data)

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

    if args["md5"]:
        with console.status(
            f"[bold green] Fetching OSINT from Alien Vault for {args['md5']}..."
        ):
            try:
                otx_data = otx.get_indicator_details_full(
                    IndicatorTypes.FILE_HASH_MD5, args["md5"]
                )
            except Exception as e:
                print(e)
                return None
            pprint.pprint(otx_data)

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
