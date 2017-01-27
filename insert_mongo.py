from pymongo import MongoClient


def store_cve(db, package, os, version, cve, status, priority):
    db.cve_ubuntu.insert_one(
        {
            "package": package.lower(),
            "os": os.lower(),
            "version": version.lower(),
            "cve": cve.lower(),
            "status": status.lower(),
            "priority": priority.lower(),
        })


def main():
    client = MongoClient()
    db = client.cve_ubuntu
    with open("cves.out") as file:
        for line in file:
            line = line.rstrip('\n')
            package = line.split(";")[0]
            os = line.split(";")[1]
            version = line.split(";")[2]
            cve = line.split(";")[3]
            status = line.split(";")[4]
            priority = line.split(";")[5]
            store_cve(db, package, os, version, cve, status, priority)


if __name__ == "__main__":
    main()
