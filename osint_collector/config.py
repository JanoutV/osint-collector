from pathlib import Path
from configparser import ConfigParser


class Config:

    config_parser = ConfigParser()
    ## since we don't want to rely on the current working directory, this should ensure
    # that wherever the file is executed, it always loads config ini which is in the
    # same directory as config.py
    config_file_path = Path(__file__).parents[0].joinpath("config.ini")

    if config_file_path.exists():
        config_parser.read(config_file_path)
    else:
        print("No config.ini file present.")
    ## this method accessses the config.ini file returns corresponding API key
    @classmethod
    def get_value_from_conf(cls, key):
        return cls.config_parser.get("API_KEYS", key)
