# cve-ubuntu-search
cve-ubuntu-search is a tool to import USN (Ubuntu Security Notices) database dump into a MongoDB to facilitate search and processing of CVEs and its packages.
Given (.deb) packages with their versions, you can check if there are known vulnerabilities that affects them.

*Dump last updated: 01/21/2017*

# Requirements
   * MongoDB (2.2 or above)
   * Python3
   * Pip3:
     * PyMongo
     * natsort

# Installation
1. First we install the requirements:

    ```
    sudo pip3 install requirements
    ```
2. MongoDB installation: you can get the distribution packages here: https://docs.mongodb.com/manual/installation/.
If Ubuntu, here is the guide: https://docs.mongodb.com/manual/tutorial/install-mongodb-on-ubuntu/
3. We populate the MongoDB with Ubuntu's CVEs dump (should take 15-20 seconds):

    ```
    $ python3 insert_mongo.py
    ```
4. We are ready to go!

# Usage
```
$ python3 search.py -h
usage: search.py [-h] [-p PACKAGE] [-v VERSION] [-o OS] [-c CVE]

CVE Ubuntu Search.

optional arguments:
  -h, --help            show this help message and exit
  -p PACKAGE, --package PACKAGE
                        package --> e.g: -p php5
  -v VERSION, --version VERSION
                        package version (optional) --> e.g: -p php5 -v 5.2.1
  -o OS, --os OS        OS or upstream --> e.g: -o 14.04
  -c CVE, --cve CVE     Specific CVE information --> -c CVE-2015-1258
```

# Examples
1. Listing all CVEs:

    ```
    $ python3 search.py | wc -l
    53838
    ```
    ```
    $ python3 search.py | head
    cve-2014-4207: Package mysql-5.5, fix version: 5.5.38-0ubuntu0.12.04.1 [Ubuntu 12.04 Lts (Precise Pangolin)] (http://people.canonical.com/~ubuntu-security/cve/2014/CVE-2014-4207.html)
    cve-2014-4207: Package mysql-5.5, fix version: 5.5.38-0ubuntu0.14.04.1 [Ubuntu 14.04 Lts (Trusty Tahr)] (http://people.canonical.com/~ubuntu-security/cve/2014/CVE-2014-4207.html)
    cve-2014-4207: Package mariadb-5.5, fix version: 5.5.38 [Upstream] (http://people.canonical.com/~ubuntu-security/cve/2014/CVE-2014-4207.html)
    cve-2014-4207: Package mariadb-5.5, fix version: 5.5.39-0ubuntu0.14.04.1 [Ubuntu 14.04 Lts (Trusty Tahr)] (http://people.canonical.com/~ubuntu-security/cve/2014/CVE-2014-4207.html)
    ```
2. You can also search for a specific package:

    ```
    $ python3 search.py -p redis
    cve-2016-8339: Package redis, fix version: 3:3.2.4-1 [Upstream] (http://people.canonical.com/~ubuntu-security/cve/2016/CVE-2016-8339.html)
    cve-2013-7458: Package redis, fix version: 2:3.2.1-4 [Upstream] (http://people.canonical.com/~ubuntu-security/cve/2013/CVE-2013-7458.html)
    cve-2015-4335: Package redis, fix version: 2:3.0.2-1 [Upstream] (http://people.canonical.com/~ubuntu-security/cve/2015/CVE-2015-4335.html)
    cve-2013-0180: Package redis, fix version: 2:2.6.7-1 [Upstream] (http://people.canonical.com/~ubuntu-security/cve/2013/CVE-2013-0180.html)
    ```
3. If you use X version, you can check if there are vulnerabilities with a newer version (making yours vulnerable):

    ```
    $ python3 search.py -p c-ares -v 1.10.0
    cve-2016-5180: Package c-ares, fix version: 1.12.0 [Upstream] (http://people.canonical.com/~ubuntu-security/cve/2016/CVE-2016-5180.html)
    cve-2016-5180: Package c-ares, fix version: 1.10.0-2ubuntu0.1 [Ubuntu 14.04 Lts (Trusty Tahr)] (http://people.canonical.com/~ubuntu-security/cve/2016/CVE-2016-5180.html)
    cve-2016-5180: Package c-ares, fix version: 1.10.0-3ubuntu0.1 [Ubuntu 16.04 Lts (Xenial Xerus)] (http://people.canonical.com/~ubuntu-security/cve/2016/CVE-2016-5180.html)
    cve-2016-5180: Package c-ares, fix version: 1.11.0-1ubuntu0.1 [Ubuntu 16.10 (Yakkety Yak)] (http://people.canonical.com/~ubuntu-security/cve/2016/CVE-2016-5180.html)
    ```
4. You can limit your search for a specific OS version too:

    ```
    $ python3 search.py -p nginx -v 1.4.6-1ubuntu3.4 -o 14.04
    cve-2016-4450: Package nginx, fix version: 1.4.6-1ubuntu3.5 [Ubuntu 14.04 Lts (Trusty Tahr)] (http://people.canonical.com/~ubuntu-security/cve/2016/CVE-2016-4450.html)
    cve-2016-1247: Package nginx, fix version: 1.4.6-1ubuntu3.6 [Ubuntu 14.04 Lts (Trusty Tahr)] (http://people.canonical.com/~ubuntu-security/cve/2016/CVE-2016-1247.html)
    ```
5. Information about certain CVE:

    ```
    $ python3 search.py -c CVE-2013-7341
    cve-2013-7341: Package moodle, fix version: 2.5.5 [Upstream] (http://people.canonical.com/~ubuntu-security/cve/2013/CVE-2013-7341.html)

    ```
