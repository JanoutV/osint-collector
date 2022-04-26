# from OTXv2 import OTXv2
# import IndicatorTypes
# import argparse
from config import Config
from pathlib import Path


def main():
    try:
        token = Config.get_value_from_conf("TOKEN")
    except Exception:
        raise AttributeError("Error getting config attributes.")

    print(token)
    print(Path(__file__).parents[0])


if __name__ == "__main__":
    main()
