from pymongo import MongoClient


def store_cve(db, package, os, version, cve):
    db.cve_ubuntu.insert_one(
        {
            "package": package,
            "os": os,
            "version": version,
            "cve": cve
        })


def main():
    client = MongoClient()
    db = client.cve_ubuntu
    with open("cves.out") as file:
        for line in file:
            package = line.split(";")[0]
            os = line.split(";")[1]
            version = line.split(";")[2]
            cve = line.split(";")[3]
            store_cve(db, package, os, version, cve)


if __name__ == "__main__":
    main()
