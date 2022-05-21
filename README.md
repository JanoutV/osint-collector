# osint-collector
OSINT Collector - Tool for OSINT analysis

## How to install

```bash
cd osint-collector
pip/pip3 install virtualenv
virtualenv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Add API keys to `config.ini` in this format
`config.ini`

```ini
[API_KEYS]
AVT = <API_KEY_FROM_ALIEN_VAULT>
VT = <API_KEY_FROM_VIRUS_TOTAL>
ABUSE = <API_KEY_FROM_ABUSEIPDB>
```

## Launch using python3 within the virtual environment

```bash
python3 osint_collector/oc.py --help
usage: oc.py [-h] [-d DOMAIN] [-a] [-i IP] [-u URL] [-H HASH] [-p PULSE] [-s]

OSINT Collector

optional arguments:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        Domain, for example: vut.cz
  -a, --all             Get unfiltered, unformated output from the API's.
  -i IP, --ip IP        IPv4 eg: 8.8.8.8
  -u URL, --url URL     URL eg; http://www.vut.cz
  -H HASH, --hash HASH  Hash of a file, MD5, SHA256, etc.
  -p PULSE, --pulse PULSE
                        Search OTX pulses for a string eg: Dridex
  -s, --subscribed      Get Alien Vault pulses you are subscribed to

OSINT Collector, Written by Vladimir Janout, 2022, xjanou19@vut.cz
```

