# cve-ubuntu-search
cve-ubuntu-search is a tool to import USN (Ubuntu Security Notices) database dump into a MongoDB to facilitate search and processing of CVEs and its packages.

Given (.deb) packages, you can check if there are known vulnerabilities that affects them.

*Dump last updated: 01/21/2017, run db_update.py to update it!*

# Requirements
   * MongoDB (2.2 or above)
   * Python3
   * Pip3:
     * PyMongo
     * natsort
     * beautifulsoup4
     * requests

# Installation
1. First we install the requirements:

    ```
    sudo pip3 install requirements
    ```
2. MongoDB installation: you can get the distribution packages here: https://docs.mongodb.com/manual/installation/.
If Ubuntu, here is the guide: https://docs.mongodb.com/manual/tutorial/install-mongodb-on-ubuntu/
3. We populate the MongoDB with Ubuntu's CVEs dump (should take 1 minute aprox):

    ```
    $ python3 insert_mongo.py
    ```
4. We update the MongoDB with the newest Ubuntu's CVEs:

    ```
    $ python3 db_update.py
    ```
5. We are ready to go!

# Usage
```
$ python3 search.py -h
usage: search.py [-h] [-p PACKAGE] [-v VERSION] [-o OS] [-c CVE] [-a]

CVE Ubuntu Search.

optional arguments:
  -h, --help            show this help message and exit
  -p PACKAGE, --package PACKAGE
                        package --> e.g: -p php5
  -v VERSION, --version VERSION
                        package version (optional) --> e.g: -p php5 -v 5.2.1
  -o OS, --os OS        OS or upstream --> e.g: -o 14.04
  -c CVE, --cve CVE     Specific CVE information --> -c CVE-2015-1258
  -a, --all             Show unclassified CVEs (no fix or not Ubuntu related)
```

# Examples
1. Listing all CVEs:

    ```
    $ python3 search.py | wc -l
    53831
    ```
    You can also list unclassified CVEs (with no fix version or not Ubuntu related):
    
    ```
    $ python3 search.py -a | wc -l
    120998
    ```
    Example:
    ```
    $ python3 search.py | head
    CVE-2015-0233: Package 389-admin, fix version: 1.1.38-1 [Upstream] (http://people.canonical.com/~ubuntu-security/cve/2015/CVE-2015-0233.html)
    CVE-2015-3230: Package 389-ds-base, fix version: 1.3.4.9-1 [Ubuntu 16.04 Lts (Xenial Xerus)] (http://people.canonical.com/~ubuntu-security/cve/2015/CVE-2015-3230.html)
    CVE-2012-0833: Package 389-ds-base, fix version: 1.2.10 [Upstream] (http://people.canonical.com/~ubuntu-security/cve/2012/CVE-2012-0833.html)
    CVE-2012-4450: Package 389-ds-base, fix version: 1.2.11.16 [Upstream] (http://people.canonical.com/~ubuntu-security/cve/2012/CVE-2012-4450.html)
    CVE-2012-2678: Package 389-ds-base, fix version: 1.2.11.6 [Upstream] (http://people.canonical.com/~ubuntu-security/cve/2012/CVE-2012-2678.html)
    [...]
    ```
2. You can also search for a specific package:

    ```
    $ python3 search.py -p redis
    CVE-2016-8339: Package redis, fix version: 3:3.2.4-1 [Upstream] (http://people.canonical.com/~ubuntu-security/cve/2016/CVE-2016-8339.html)
    CVE-2013-7458: Package redis, fix version: 2:3.2.1-4 [Upstream] (http://people.canonical.com/~ubuntu-security/cve/2013/CVE-2013-7458.html)
    CVE-2015-4335: Package redis, fix version: 2:3.0.2-1 [Upstream] (http://people.canonical.com/~ubuntu-security/cve/2015/CVE-2015-4335.html)
    CVE-2013-0180: Package redis, fix version: 2:2.6.7-1 [Upstream] (http://people.canonical.com/~ubuntu-security/cve/2013/CVE-2013-0180.html)
    ```
3. If you use X version, you can check if there are vulnerabilities for a newer version (making yours vulnerable):

    ```
    $ python3 search.py -p c-ares -v 1.10.0
    CVE-2016-5180: Package c-ares, fix version: 1.12.0 [Upstream] (http://people.canonical.com/~ubuntu-security/cve/2016/CVE-2016-5180.html)
    CVE-2016-5180: Package c-ares, fix version: 1.10.0-2ubuntu0.1 [Ubuntu 14.04 Lts (Trusty Tahr)] (http://people.canonical.com/~ubuntu-security/cve/2016/CVE-2016-5180.html)
    CVE-2016-5180: Package c-ares, fix version: 1.10.0-3ubuntu0.1 [Ubuntu 16.04 Lts (Xenial Xerus)] (http://people.canonical.com/~ubuntu-security/cve/2016/CVE-2016-5180.html)
    CVE-2016-5180: Package c-ares, fix version: 1.11.0-1ubuntu0.1 [Ubuntu 16.10 (Yakkety Yak)] (http://people.canonical.com/~ubuntu-security/cve/2016/CVE-2016-5180.html)
    ```
4. You can limit your search for a specific OS version too:

    ```
    $ python3 search.py -p nginx -v 1.4.6-1ubuntu3.4 -o 14.04
    CVE-2016-4450: Package nginx, fix version: 1.4.6-1ubuntu3.5 [Ubuntu 14.04 Lts (Trusty Tahr)] (http://people.canonical.com/~ubuntu-security/cve/2016/CVE-2016-4450.html)
    CVE-2016-1247: Package nginx, fix version: 1.4.6-1ubuntu3.6 [Ubuntu 14.04 Lts (Trusty Tahr)] (http://people.canonical.com/~ubuntu-security/cve/2016/CVE-2016-1247.html)
    ```
    If you also want to know if there are CVEs for a package without fix versions, try -a:
    
    ```
    $ python3 search.py -p nginx -v 1.4.6-1ubuntu3.4 -o 14.04
    CVE-2016-4450: Package nginx, fix version: 1.4.6-1ubuntu3.5 [Ubuntu 14.04 Lts (Trusty Tahr)] (http://people.canonical.com/~ubuntu-security/cve/2016/CVE-2016-4450.html)
    CVE-2016-1247: Package nginx, fix version: 1.4.6-1ubuntu3.6 [Ubuntu 14.04 Lts (Trusty Tahr)] (http://people.canonical.com/~ubuntu-security/cve/2016/CVE-2016-1247.html)
    luke@lukelandia:~/whiteduck/cve_ubuntu$ python3 search.py -p nginx -v 1.4.6-1ubuntu3.4 -o 14.04 -a
    CVE-2016-4450: Package nginx, fix version: 1.4.6-1ubuntu3.5 [Ubuntu 14.04 Lts (Trusty Tahr)] (http://people.canonical.com/~ubuntu-security/cve/2016/CVE-2016-4450.html)
    CVE-2016-1247: Package nginx, fix version: 1.4.6-1ubuntu3.6 [Ubuntu 14.04 Lts (Trusty Tahr)] (http://people.canonical.com/~ubuntu-security/cve/2016/CVE-2016-1247.html)
    CVE-2013-0337: Package nginx doesn't have a released fix version [Ubuntu 14.04 Lts (Trusty Tahr)]
    ```

5. Information about certain CVE:

    ```
    $ python3 search.py -c CVE-2013-7341
    CVE-2013-7341: Package moodle, fix version: 2.5.5 [Upstream] (http://people.canonical.com/~ubuntu-security/cve/2013/CVE-2013-7341.html)
    CVE-2013-7341: Package moodle doesn't have a released fix version [Ubuntu 14.04 Lts (Trusty Tahr)]
    CVE-2013-7341: Package moodle doesn't have a released fix version [Ubuntu 16.04 Lts (Xenial Xerus)]
    CVE-2013-7341: Package moodle doesn't have a released fix version [Ubuntu 16.10 (Yakkety Yak)]
    ```
