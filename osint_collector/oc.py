from OTXv2 import OTXv2
import IndicatorTypes
import argparse
from config import Config
from rich.console import Console
import pandas as pd
import pprint
import traceback


def main():
    parser = argparse.ArgumentParser(
        description="OSINT querry tool",
        add_help=True,
        epilog="OSINT Collector, Written by Vladimir Janout, 2022",
    )
    parser.add_argument(
        "-d", "--domain", help="Domain, for example: vut.cz", required=False
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

    try:
        token = Config.get_value_from_conf("TOKEN")
    except Exception:
        raise AttributeError("Error getting config attributes.")

    # Establish connection with OTX -> future work with try, catch block
    otx = OTXv2(token)
    console = Console()

    args = vars(parser.parse_args())

    if args["ip"]:
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
            pprint.pprint(otx_data)

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
