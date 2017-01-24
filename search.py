import argparse
import re
from pymongo import MongoClient
from natsort import natsorted


def search(data):
    client = MongoClient()
    db = client.cve_ubuntu
    return db.cve_ubuntu.find(data)


def get_args():
    parser = argparse.ArgumentParser(description='CVE Ubuntu Search.')
    parser.add_argument('-p', '--package',  help='package --> e.g: -p php5')
    parser.add_argument('-v', '--version',  help='package version (optional) --> e.g: -p php5 -v 5.2.1')
    parser.add_argument('-o', '--os', help='OS or upstream -->  e.g: -o 14.04')
    parser.add_argument('-c', '--cve', help='Specific CVE information --> -c CVE-2015-1258')
    args = parser.parse_args()
    package = args.package
    version = args.version
    os = args.os
    cve = args.cve
    return package, version, os, cve


def create_link(cve):
    year = cve.split("-")[1]
    url = "http://people.canonical.com/~ubuntu-security/cve/{}/{}.html".format(year, cve.upper())
    return url


def version_is_vulnerable(version, cve_version):
    l = []
    l.append(version)
    l.append(cve_version)
    if natsorted(l).index(version) < natsorted(l).index(cve_version):
        return True
    return False


def main():
    package, version, os, cve = get_args()
    data = {}
    if package:
        data['package'] = package
    if os:
        data['os'] = re.compile('.*{}.*'.format(os))
    if cve:
        data['cve'] = cve.lower()
    results = search(data)
    for result in results:
        link = create_link(result['cve'])
        if version:  # if user provided a version
            if version_is_vulnerable(version, result['version']):  # we check if version is vulnerable for each case
                print("{}: Package {}, fix version: {} [{}] ({})".format(result['cve'], result['package'],
                                                                    result['version'], result['os'].title(), link))
        else:
            print("{}: Package {}, fix version: {} [{}] ({})".format(result['cve'], result['package'],
                                                                result['version'], result['os'].title(), link))


if __name__ == "__main__":
    main()
