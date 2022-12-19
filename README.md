# ZAP-scipts

Collection of my own sciprt which are usually duplicates from scripts already there

|Name|Type|Description|
|---|---|---|
|Find Addlistener.js|passive|Script looking for addEventListener in body|
|CryptoMiners.py|passive|Search for known crypto domain in body|
|Censys Search.py|targeted|Open system browser with censys search for specific IP|

### Find Addlistener.js 

Look for addEventListener for potentionally execute DOM XSS vulnerability

### CryptoMiners.py

Heavy inspired Codingo script for burpsuite but this working in ZAP proxy. Script looking for known domains that host cryptomining javascrips. 

### Censys Search

I like to search for servers on censys website. This script automate this feature

