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
