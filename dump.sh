#!/bin/bash

mongoexport --host localhost --db cve_ubuntu --collection cve_ubuntu --type=csv --out cves.out --fields package,os,version,cve,status,priority
tail -n +2 cves.out > cves.out.tmp

rm cves.out
python3 add_quotes.py
rm cves.out.tmp
