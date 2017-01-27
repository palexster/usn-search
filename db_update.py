import re
import datetime
import requests
from pymongo import MongoClient
from bs4 import BeautifulSoup
from insert_mongo import store_cve


def verify_status(status):
    if status == "released" or status == "ignored" or status == "not-affected" or status == "needed" or status == "ignored" or status == "needs-triage" or status == "DNE":
        return True
    return False


def parse_cve_page(db, html, cve):
    soup = BeautifulSoup(html, "lxml")
    packages = soup.find_all("div", class_="pkg")
    print("Storing {}...".format(cve))
    if packages:
        for package in packages:
            package_name = package.find("div", class_="value").a.text
            for tr in package.find_all("tr"):
                if len(tr.find_all("td")[1].text.split()) >= 1:
                    ubuntu = tr.find_all("td")[0].text.partition(":")[0]
                    status = tr.find_all("td")[1].text.split()[0]
                    priority = soup.find("div", class_="item").find_all("div")[1].text
                    if 'released' in tr.find_all("td")[1].text and len(tr.find_all("td")[1].text.split()) > 1:
                        version = tr.find_all("td")[1].text.split()[1].split("(")[1].split(")")[0]
                        store_cve(db, package_name, ubuntu, version, cve, status, priority)
                    elif verify_status(status):
                        store_cve(db, package_name, ubuntu, "", cve, status, priority)
                else:
                    store_cve(db, "", "", "", cve, "", "")
    else:
        store_cve(db, "", "", "", cve, "", "")


def export_cves():
    cves = set()
    client = MongoClient()
    db = client.cve_ubuntu
    result = db.cve_ubuntu.find({}, {'cve': 1, '_id': 0})
    for document in result:
        cves.add(document['cve'])
    return cves


def check_cve_ubuntu(db):
    missing = set()
    this_year = datetime.datetime.now().year
    cves = export_cves()
    for year in range(1999, this_year+1):
        count = 0
        print("Checking {}... ".format(year), end="")
        r = requests.get("http://people.canonical.com/~ubuntu-security/cve/{}/".format(year))
        try:
            r.raise_for_status()
            target = re.compile("CVE-\d+-\d+")
            cves_regex = re.findall(target, r.text)
            for cve in cves_regex:
                if cve.lower() not in cves:  # cve doesnt exist, we need to create it
                    if cve not in missing:
                        missing.add(cve)
                        count += 1
            print("{}/{}".format(len(cves_regex) - count, len(cves_regex)))
        except requests.exceptions.HTTPError as e:
            print('Error.')
    print("Total missing: {}".format(len(missing)))
    return missing


def download_cves(db, missing):
    for cve in missing:
        year = cve.split("-")[1]
        r = requests.get("http://people.canonical.com/~ubuntu-security/cve/{}/{}.html".format(year, cve))
        parse_cve_page(db, r.text, cve)


def main():
    client = MongoClient()
    db = client.cve_ubuntu
    missing = check_cve_ubuntu(db)
    if missing:
        download_cves(db, missing)
    else:
        print("Nothing to update.")


if __name__ == "__main__":
    main()
