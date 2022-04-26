from OTXv2 import OTXv2
import IndicatorTypes
import argparse
from config import Config


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
        help="Get pulses you are subscribed to",
        required=False,
        action="store_true",
    )

    try:
        token = Config.get_value_from_conf("TOKEN")
    except Exception:
        raise AttributeError("Error getting config attributes.")

    # Establish connection with OTX -> future work with try, catch block
    otx = OTXv2(token)

    args = vars(parser.parse_args())

    if args["ip"]:
        print(str(otx.get_indicator_details_full(IndicatorTypes.IPv4, args["ip"])))

    if args["domain"]:
        print(
            str(otx.get_indicator_details_full(IndicatorTypes.DOMAIN, args["domain"]))
        )

    if args["hostname"]:
        print(
            str(
                otx.get_indicator_details_full(
                    IndicatorTypes.HOSTNAME, args["hostname"]
                )
            )
        )

    if args["url"]:
        print(str(otx.get_indicator_details_full(IndicatorTypes.URL, args["url"])))

    if args["md5"]:
        print(
            str(
                otx.get_indicator_details_full(
                    IndicatorTypes.FILE_HASH_MD5, args["md5"]
                )
            )
        )

    if args["pulse"]:
        result = otx.search_pulses(args["pulse"])
        print(str(result.get("results")))

    if args["subscribed"]:
        print(str(otx.getall(max_items=3, limit=5)))


if __name__ == "__main__":
    main()
