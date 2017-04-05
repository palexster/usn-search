#!/bin/bash

mongoexport --host localhost --db cve_ubuntu --collection cve_ubuntu --csv --out cves.out --fields package,os,version,cve,status,priority
tail -n +2 cves.out > cves.out.tmp && mv cves.out.tmp cves.out