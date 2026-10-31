#!/usr/bin/env python3
"""catalog_gen.py VULHUB_DIR [OUT]: writes catalog.json from a Vulhub checkout.

The picks below are the hand-chosen environments: light (no GitLab,
Confluence, WebLogic), x86, started by a plain `docker compose up -d`, with
nothing to install or click through first. Everything else (images, ports,
CVE ids, the one-line summary) is read from the checkout's compose files and
READMEs, so the catalog is pinned to the commit it was built from. Needs
PyYAML (this script runs on a developer machine, not in CI).

Pick fields: path, product, family (a product family appears once per
estate), version, category, the primary port and its probe, the memory the
whole environment is expected to need (MB), the seconds it is expected to
take to answer, and optional extras:
  proto   {port: protocol} for ports that are not plain HTTP
  names   host names an operator might give it (product-flavoured)
  proxy   True when the app works behind a Host-routing reverse proxy
  cve     override of the ids read from the path and README
  note    override of the one-line summary
"""
import glob
import json
import os
import re
import subprocess
import sys

CATEGORIES = ["ci-cd", "cms", "framework", "datastore", "admin-panel",
              "middleware", "messaging", "monitoring", "mail-other"]

# Protocols by container port, when a pick does not say otherwise.
PORT_PROTO = {
    22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 445: "smb", 631: "ipp",
    873: "rsync", 1099: "java-rmi", 1337: "java-rmi", 2181: "zookeeper",
    3306: "mysql", 4369: "epmd", 4505: "zeromq", 4506: "zeromq",
    4712: "tcp", 5005: "jdwp", 5432: "postgresql", 6123: "tcp",
    6379: "redis", 6699: "tcp", 7077: "tcp", 7687: "bolt", 8009: "ajp13",
    9300: "tcp", 9876: "rocketmq", 10911: "rocketmq", 11211: "memcached",
    34444: "java-rmi", 50000: "jenkins-agent", 61616: "openwire",
    64000: "java-rmi",
}
HTTPS_PORTS = {443, 8443, 9443, 10000}

# Probe shorthand: h:/path (HTTP, answer below 500), hs:/path (HTTPS),
# t (TCP, held open), or a protocol name with a banner or a request.
BANNER = {
    "ssh": {"kind": "tcp", "expect": "^SSH-"},
    "redis": {"kind": "tcp", "send": "PING\r\n", "expect": "PONG|NOAUTH"},
    "mysql": {"kind": "tcp", "expect": "[0-9]\\.[0-9]"},
    "pg": {"kind": "tcp", "send_hex": "0000000804d2162f", "expect": "^[NS]"},
    "smtp": {"kind": "tcp", "expect": "^220"},
    "zk": {"kind": "tcp", "send": "ruok", "expect": "imok"},
    "amq": {"kind": "tcp", "expect": "ActiveMQ"},
    "dns": {"kind": "dns-tcp", "name": "version.bind."},
    "t": {"kind": "tcp"},
}


def P(path, product, family, version, category, primary, probe, mem, ready, **kw):
    kw.update(path=path, product=product, family=family, version=version,
              category=category, primary=primary, probe=probe,
              mem_mb=mem, ready_s=ready)
    return kw


PICKS = [
    # ci-cd
    P("jenkins/CVE-2017-1000353", "Jenkins", "jenkins", "2.46.1", "ci-cd", 8080, "h:/login", 550, 90, proto={50000: "jenkins-agent"}, names=["ci", "jenkins", "build"], proxy=True),
    P("jenkins/CVE-2018-1000861", "Jenkins", "jenkins", "2.138", "ci-cd", 8080, "h:/login", 550, 90, proto={50000: "jenkins-agent"}, names=["ci", "jenkins", "build"], proxy=True),
    P("jenkins/CVE-2024-23897", "Jenkins", "jenkins", "2.441", "ci-cd", 8080, "h:/login", 600, 90, proto={50000: "jenkins-agent"}, names=["ci", "jenkins", "build"], proxy=True),
    P("nexus/CVE-2020-10199", "Sonatype Nexus Repository", "nexus", "3.21.1", "ci-cd", 8081, "h:/", 1300, 240, names=["artifacts", "nexus", "repo"], proxy=True),
    P("nexus/CVE-2024-4956", "Sonatype Nexus Repository", "nexus", "3.68.0", "ci-cd", 8081, "h:/", 1400, 240, names=["artifacts", "nexus", "repo"], proxy=True),
    P("xxl-job/unacc", "XXL-JOB", "xxl-job", "2.2.0", "ci-cd", 8080, "h:/", 700, 120, names=["jobs", "scheduler", "cron"], proxy=True),
    P("saltstack/CVE-2020-11651", "SaltStack Salt master", "salt", "2019.2.3", "ci-cd", 8000, "h:/", 250, 60, names=["salt", "config", "ops"]),
    P("git/CVE-2017-8386", "Git over SSH (git-shell)", "git", "2.12.2", "ci-cd", 3322, "ssh", 60, 20, names=["git", "scm", "code"]),
    # cms
    P("wordpress/CVE-2026-63030", "WordPress", "wordpress", "6.9.4", "cms", 8080, "h:/", 550, 120, names=["blog", "www", "wp", "site", "marketing"], proxy=True),
    P("joomla/CVE-2023-23752", "Joomla!", "joomla", "4.2.7", "cms", 8080, "h:/", 450, 90, names=["www", "news", "portal", "site"], proxy=True),
    P("joomla/CVE-2017-8917", "Joomla!", "joomla", "3.7.0", "cms", 8080, "h:/", 350, 90, names=["www", "news", "portal", "site"], proxy=True),
    P("joomla/CVE-2015-8562", "Joomla!", "joomla", "3.4.5", "cms", 8080, "h:/", 330, 90, names=["old", "intranet", "www2"], proxy=True),
    P("tikiwiki/CVE-2020-15906", "Tiki Wiki CMS Groupware", "tikiwiki", "21.1", "cms", 8080, "h:/", 500, 120, names=["wiki", "kb", "docs"], proxy=True),
    P("showdoc/CNVD-2020-26585", "ShowDoc", "showdoc", "2.8.2", "cms", 8080, "h:/", 120, 40, names=["docs", "api-docs", "showdoc"], proxy=True),
    P("showdoc/3.2.5-sqli", "ShowDoc", "showdoc", "3.2.4", "cms", 8080, "h:/", 130, 40, names=["docs", "api-docs", "showdoc"], proxy=True),
    P("v2board/1.6-privilege-escalation", "V2Board", "v2board", "1.6.1", "cms", 8080, "h:/", 500, 90, names=["panel", "portal", "billing"], proxy=True),
    P("owncloud/CVE-2023-49103", "ownCloud", "owncloud", "10.12.1", "cms", 8080, "h:/", 450, 120, names=["files", "cloud", "share"], proxy=True),
    # framework
    P("struts2/s2-045", "Apache Struts", "struts2", "2.3.30", "framework", 8080, "h:/", 400, 60, names=["app", "portal", "legacy"], proxy=True),
    P("struts2/s2-061", "Apache Struts", "struts2", "2.5.25", "framework", 8080, "h:/", 400, 60, names=["app", "portal", "web"], proxy=True),
    P("spring/CVE-2022-22965", "Spring Framework (Spring MVC)", "spring", "5.3.17", "framework", 8080, "h:/", 350, 60, names=["api", "service", "app"], proxy=True),
    P("spring/CVE-2022-22947", "Spring Cloud Gateway", "spring", "3.1.0", "framework", 8080, "h:/", 400, 60, names=["gateway", "gw", "edge-api"], proxy=True),
    P("thinkphp/5-rce", "ThinkPHP", "thinkphp", "5.0.20", "framework", 8080, "h:/", 60, 30, names=["shop", "app", "mall"], proxy=True),
    P("laravel/CVE-2021-3129", "Laravel (Ignition)", "laravel", "8.4.2", "framework", 8080, "h:/", 80, 30, names=["app", "dash", "portal"], proxy=True),
    P("django/CVE-2018-14574", "Django", "django", "2.0.7", "framework", 8000, "h:/", 80, 30, names=["app", "web", "backend"], proxy=True),
    P("fastjson/1.2.24-rce", "Fastjson (Spring Boot app)", "fastjson", "1.2.24", "framework", 8090, "h:/", 300, 40, names=["api", "service", "rest"], proxy=True),
    P("shiro/CVE-2016-4437", "Apache Shiro", "shiro", "1.2.4", "framework", 8080, "h:/", 350, 60, names=["admin", "portal", "oa"], proxy=True),
    P("rails/CVE-2018-3760", "Ruby on Rails", "rails", "5.0.7", "framework", 3000, "h:/", 200, 40, names=["app", "web", "rails"], proxy=True),
    P("next.js/CVE-2025-29927", "Next.js", "nextjs", "15.2.2", "framework", 3000, "h:/", 200, 30, names=["app", "dashboard", "web"], proxy=True),
    P("flask/ssti", "Flask", "flask", "1.1.1", "framework", 8000, "h:/", 50, 20, names=["tools", "util", "internal"], proxy=True),
    P("gradio/CVE-2024-1561", "Gradio", "gradio", "4.12.0", "framework", 7860, "h:/", 300, 40, names=["ml", "demo", "ai"], proxy=True),
    # datastore
    P("redis/4-unacc", "Redis", "redis", "4.0.14", "datastore", 6379, "redis", 20, 10, names=["cache", "redis", "kv"]),
    P("redis/CVE-2022-0543", "Redis (Debian build)", "redis", "5.0.7", "datastore", 6379, "redis", 20, 10, names=["cache", "redis", "session"]),
    P("couchdb/CVE-2022-24706", "Apache CouchDB", "couchdb", "3.2.1", "datastore", 5984, "h:/", 150, 40, proto={4369: "epmd", 9100: "erlang-dist"}, names=["couch", "db", "docs-db"], proxy=True),
    P("elasticsearch/CVE-2014-3120", "Elasticsearch", "elasticsearch", "1.1.1", "datastore", 9200, "h:/", 450, 60, proto={9300: "elasticsearch-transport"}, names=["search", "es", "logs"], proxy=True),
    P("elasticsearch/CVE-2015-1427", "Elasticsearch", "elasticsearch", "1.4.2", "datastore", 9200, "h:/", 450, 60, proto={9300: "elasticsearch-transport"}, names=["search", "es", "index"], proxy=True),
    P("mysql/CVE-2012-2122", "MySQL", "mysql", "5.5.23", "datastore", 3306, "mysql", 200, 30, names=["db", "mysql", "sql"]),
    P("postgres/CVE-2018-1058", "PostgreSQL", "postgres", "9.6.7", "datastore", 5432, "pg", 60, 20, names=["db", "pg", "postgres"]),
    P("influxdb/CVE-2019-20933", "InfluxDB", "influxdb", "1.6.6", "datastore", 8086, "h:/ping", 60, 20, names=["metrics-db", "influx", "tsdb"], proxy=True),
    P("neo4j/CVE-2021-34371", "Neo4j", "neo4j", "3.4.18", "datastore", 7474, "h:/", 600, 60, names=["graph", "neo4j", "kg"], proxy=True),
    P("solr/CVE-2019-17558", "Apache Solr", "solr", "8.2.0", "datastore", 8983, "h:/solr/", 550, 60, names=["solr", "search", "catalog"], proxy=True),
    P("h2database/CVE-2018-10054", "H2 Database console (Spring app)", "h2", "1.4.197", "datastore", 8080, "h:/", 350, 60, names=["db-admin", "h2", "devdb"], proxy=True),
    P("hugegraph/CVE-2024-27348", "Apache HugeGraph", "hugegraph", "1.2.0", "datastore", 8080, "h:/", 700, 90, names=["graph", "hugegraph", "kg"], proxy=True),
    # admin-panel
    P("phpmyadmin/CVE-2018-12613", "phpMyAdmin", "phpmyadmin", "4.8.1", "admin-panel", 8080, "h:/", 250, 60, names=["pma", "phpmyadmin", "dbadmin"], proxy=True),
    P("phpmyadmin/CVE-2016-5734", "phpMyAdmin", "phpmyadmin", "4.4.15.6", "admin-panel", 8080, "h:/", 250, 60, names=["pma", "phpmyadmin", "dbadmin"], proxy=True),
    P("adminer/CVE-2021-21311", "Adminer", "adminer", "4.7.8", "admin-panel", 8080, "h:/", 40, 15, names=["adminer", "dbtool", "sql"], proxy=True),
    P("pgadmin/CVE-2022-4223", "pgAdmin 4", "pgadmin", "6.16", "admin-panel", 5050, "h:/", 300, 60, names=["pgadmin", "dbadmin", "pg-ui"], proxy=True),
    P("mongo-express/CVE-2019-10758", "mongo-express", "mongo-express", "0.53.0", "admin-panel", 8081, "h:/", 300, 40, names=["mongo", "mongo-ui", "dbadmin"], proxy=True),
    P("webmin/CVE-2019-15107", "Webmin", "webmin", "1.910", "admin-panel", 10000, "hs:/", 100, 30, names=["webmin", "sysadmin", "ops"]),
    P("supervisor/CVE-2017-11610", "Supervisor", "supervisor", "3.3.2", "admin-panel", 9001, "h:/", 40, 15, names=["supervisor", "procs", "workers"], proxy=True),
    P("glassfish/CVE-2017-1000028", "Eclipse GlassFish admin console", "glassfish", "4.1", "admin-panel", 4848, "h:/", 600, 90, names=["glassfish", "jee-admin", "appserver"], proxy=True),
    P("1panel/CVE-2024-39907", "1Panel", "1panel", "1.10.10", "admin-panel", 10086, "h:/entrance", 150, 40, names=["panel", "1panel", "hosting"], proxy=True),
    P("nginx-ui/CVE-2026-27944", "Nginx UI", "nginx-ui", "2.3.2", "admin-panel", 9000, "h:/", 100, 30, names=["nginx-ui", "edge-admin", "lb-admin"], proxy=True),
    P("jupyter/notebook-rce", "Jupyter Notebook", "jupyter", "5.2.2", "admin-panel", 8888, "h:/", 120, 30, names=["notebook", "jupyter", "ds"], proxy=True),
    P("elfinder/CVE-2021-32682", "elFinder", "elfinder", "2.1.58", "admin-panel", 8080, "h:/", 60, 20, names=["files", "fm", "assets-admin"], proxy=True),
    P("superset/CVE-2023-27524", "Apache Superset", "superset", "2.0.1", "admin-panel", 8088, "h:/", 900, 120, names=["bi", "superset", "reports"], proxy=True),
    P("openfire/CVE-2023-32315", "Openfire admin console", "openfire", "4.7.4", "admin-panel", 9090, "h:/", 450, 90, names=["chat", "xmpp", "im"], proxy=True),
    # middleware
    P("tomcat/CVE-2020-1938", "Apache Tomcat", "tomcat", "9.0.30", "middleware", 8080, "h:/", 250, 40, proto={8009: "ajp13"}, names=["tomcat", "app", "legacy"], proxy=True),
    P("tomcat/tomcat8", "Apache Tomcat (manager, weak login)", "tomcat", "8.0", "middleware", 8080, "h:/", 250, 40, names=["tomcat", "app", "old-app"], proxy=True),
    P("jboss/CVE-2017-12149", "JBoss Application Server", "jboss", "6.1.0", "middleware", 8080, "h:/", 600, 150, proto={9990: "http"}, names=["jboss", "jee", "appsrv"], proxy=True),
    P("jetty/CVE-2021-28164", "Eclipse Jetty", "jetty", "9.4.37", "middleware", 8080, "h:/", 250, 40, names=["jetty", "svc", "web"], proxy=True),
    P("apache-cxf/CVE-2024-28752", "Apache CXF", "cxf", "3.2.14", "middleware", 8080, "h:/", 300, 40, names=["soap", "ws", "cxf"], proxy=True),
    P("nginx/CVE-2017-7529", "nginx", "nginx", "1.13.2", "middleware", 8080, "h:/", 20, 10, names=["cdn", "static", "edge"], proxy=True),
    P("php/CVE-2019-11043", "nginx with PHP-FPM", "php", "7.2.10", "middleware", 8080, "h:/", 100, 20, names=["web", "php", "www"], proxy=True),
    P("php/fpm", "PHP-FPM (FastCGI exposed)", "php-fpm", "7.1.3", "middleware", 9000, "t", 60, 15, proto={9000: "fastcgi"}, names=["fpm", "php", "backend"]),
    P("php/CVE-2012-1823", "PHP (CGI mode)", "php", "5.4.1", "middleware", 8080, "h:/", 40, 15, names=["old-web", "php", "legacy"], proxy=True),
    P("uwsgi/unacc", "uWSGI behind nginx", "uwsgi", "2.0.17", "middleware", 8080, "h:/", 80, 20, proto={8000: "uwsgi"}, names=["py", "api", "uwsgi"], proxy=True),
    P("dubbo/CVE-2019-17564", "Apache Dubbo", "dubbo", "2.7.3", "middleware", 8080, "h:/", 450, 60, proto={2181: "zookeeper"}, names=["rpc", "dubbo", "svc"], proxy=True),
    P("flink/CVE-2020-17518", "Apache Flink", "flink", "1.11.2", "middleware", 8081, "h:/", 600, 60, names=["flink", "stream", "etl"], proxy=True),
    P("spark/unacc", "Apache Spark standalone", "spark", "2.3.1", "middleware", 8080, "h:/", 900, 60, proto={7077: "spark-rpc", 6066: "http", 8081: "http"}, names=["spark", "analytics", "etl"], proxy=True),
    P("nacos/CVE-2021-29441", "Nacos", "nacos", "1.4.0", "middleware", 8848, "h:/nacos/", 700, 90, names=["nacos", "config", "registry"], proxy=True),
    P("java/rmi-registry-bind-deserialization", "Java RMI registry", "java-rmi", "8u131", "middleware", 1099, "t", 60, 15, names=["rmi", "svc", "jmx"]),
    P("goahead/CVE-2017-17562", "GoAhead embedded web server", "goahead", "3.6.4", "middleware", 8080, "h:/", 20, 10, names=["device", "cam", "gw"], proxy=True),
    # messaging
    P("activemq/CVE-2015-5254", "Apache ActiveMQ", "activemq", "5.11.1", "messaging", 8161, "h:/", 450, 60, proto={61616: "openwire"}, names=["mq", "activemq", "queue"], proxy=True),
    P("activemq/CVE-2023-46604", "Apache ActiveMQ", "activemq", "5.17.3", "messaging", 8161, "h:/", 450, 60, proto={61616: "openwire"}, names=["mq", "activemq", "broker"], proxy=True),
    P("activemq/CVE-2024-32114", "Apache ActiveMQ", "activemq", "6.1.1", "messaging", 8161, "h:/", 500, 60, proto={61616: "openwire"}, names=["mq", "activemq", "queue"], proxy=True),
    P("rocketmq/CVE-2023-33246", "Apache RocketMQ broker", "rocketmq", "5.1.0", "messaging", 10911, "t", 500, 60, names=["rmq", "rocketmq", "events"]),
    P("rocketmq/CVE-2023-37582", "Apache RocketMQ name server", "rocketmq", "5.1.0", "messaging", 9876, "t", 800, 60, names=["rmq", "rocketmq", "mq-ns"]),
    P("celery/celery3_redis_unauth", "Redis (Celery 3 broker)", "redis", "latest", "messaging", 6379, "redis", 40, 10, names=["broker", "tasks", "celery"]),
    # monitoring
    P("grafana/CVE-2021-43798", "Grafana", "grafana", "8.2.6", "monitoring", 3000, "h:/login", 150, 30, names=["grafana", "metrics", "dash"], proxy=True),
    P("grafana/CVE-2024-9264", "Grafana", "grafana", "11.0.0", "monitoring", 3000, "h:/login", 200, 30, names=["grafana", "metrics", "dash"], proxy=True),
    P("grafana/admin-ssrf", "Grafana", "grafana", "8.5.4", "monitoring", 3000, "h:/login", 150, 30, names=["grafana", "metrics", "boards"], proxy=True),
    P("zabbix/CVE-2017-2824", "Zabbix", "zabbix", "3.0.3", "monitoring", 8080, "h:/", 700, 180, proto={10051: "zabbix-trapper"}, names=["zabbix", "monitor", "noc"], proxy=True),
    P("ntopng/CVE-2021-28073", "ntopng", "ntopng", "4.2", "monitoring", 3000, "h:/", 200, 40, names=["ntop", "netflow", "traffic"], proxy=True),
    P("skywalking/8.3.0-sqli", "Apache SkyWalking UI", "skywalking", "8.3.0", "monitoring", 8080, "h:/", 900, 90, names=["apm", "skywalking", "traces"], proxy=True),
    P("hertzbeat/CVE-2024-42323", "Apache HertzBeat", "hertzbeat", "1.4.4", "monitoring", 1157, "h:/", 700, 90, names=["hertzbeat", "uptime", "status"], proxy=True),
    P("opentsdb/CVE-2020-35476", "OpenTSDB", "opentsdb", "2.4.0", "monitoring", 4242, "h:/", 450, 60, names=["tsdb", "opentsdb", "series"], proxy=True),
    # mail-other
    P("opensmtpd/CVE-2020-7247", "OpenSMTPD", "opensmtpd", "6.6.1p1", "mail-other", 8825, "smtp", 20, 10, names=["mail", "smtp", "mx2"]),
    P("dns/dns-zone-transfer", "BIND (zone transfer allowed)", "bind", "9.10.3", "mail-other", 53, "dns", 40, 15, names=["ns3", "dns", "ns-int"]),
    P("samba/CVE-2017-7494", "Samba", "samba", "4.6.3", "mail-other", 445, "t", 60, 15, proto={445: "smb", 6699: "tcp"}, names=["files", "smb", "nas"]),
    P("libssh/CVE-2018-10933", "libssh server", "libssh", "0.8.1", "mail-other", 2222, "ssh", 20, 10, names=["sftp", "bastion", "jump"]),
    P("inetutils/CVE-2026-24061", "GNU inetutils telnetd", "inetutils", "2.5", "mail-other", 2323, "t", 20, 10, names=["telnet", "console", "oob"]),
    P("openssl/CVE-2014-0160", "nginx with OpenSSL 1.0.1c", "openssl", "1.0.1c", "mail-other", 8443, "t", 40, 15, names=["secure", "vpn-web", "ssl"]),
    P("php/8.1-backdoor", "PHP 8.1.0-dev", "php-dev", "8.1.0-dev", "mail-other", 8080, "h:/", 40, 15, names=["beta", "labs", "php8"], proxy=True),
    P("yapi/unacc", "YApi", "yapi", "1.9.2", "mail-other", 3000, "h:/", 400, 60, names=["yapi", "api-docs", "mock"], proxy=True),
    P("n8n/CVE-2025-68613", "n8n", "n8n", "1.65.0", "mail-other", 5678, "h:/", 350, 60, names=["n8n", "automation", "flows"], proxy=True),
    P("aria2/rce", "aria2 (RPC exposed)", "aria2", "1.18.8", "mail-other", 6800, "h:/", 20, 10, names=["dl", "aria", "fetch"], proxy=True),
]

# One-line summaries where the README's own first sentence does not say
# what is wrong.
NOTES = {
    "jenkins/CVE-2017-1000353": "Jenkins 2.46.1 LTS and earlier: unauthenticated remote code execution through the CLI remoting channel (Java deserialization).",
    "jenkins/CVE-2018-1000861": "Jenkins before 2.153: the Stapler routing lets an unauthenticated user call methods that run Groovy outside the sandbox.",
    "jenkins/CVE-2024-23897": "Jenkins before 2.442: the CLI argument parser expands @file and returns the first lines of any file the server can read.",
    "saltstack/CVE-2020-11651": "SaltStack Salt master: authentication bypass on the ZeroMQ ports (CVE-2020-11651) and directory traversal (CVE-2020-11652) give command execution and file read.",
    "git/CVE-2017-8386": "git-shell before 2.12.3 lets an SSH user with a restricted shell read arbitrary files through a crafted upload-pack path.",
    "wordpress/CVE-2026-63030": "WordPress 6.9.4: a pre-authentication chain of two core bugs creates an administrator account.",
    "joomla/CVE-2023-23752": "Joomla 4.2.7: the REST API returns the application configuration, including database credentials, to anyone who adds public=true.",
    "joomla/CVE-2017-8917": "Joomla 3.7.0: SQL injection in the com_fields component, unauthenticated.",
    "joomla/CVE-2015-8562": "Joomla 3.4.5: the session handler deserializes a crafted User-Agent header, giving unauthenticated remote code execution.",
    "tikiwiki/CVE-2020-15906": "Tiki Wiki 21.1 and earlier: after 50 failed logins the admin account is locked, and a blank password then logs in as admin.",
    "v2board/1.6-privilege-escalation": "V2Board 1.6.1: a normal user can obtain an administrator token through the API (privilege escalation).",
    "struts2/s2-045": "Apache Struts 2.3.30: S2-045, remote code execution through the Content-Type header (Jakarta multipart parser).",
    "fastjson/1.2.24-rce": "Fastjson 1.2.24: JSON parsing with autoType creates arbitrary classes, giving remote code execution.",
    "mysql/CVE-2012-2122": "MySQL 5.5.23: a wrong password is accepted about one time in 256 attempts, so repeating the login gets in.",
    "pgadmin/CVE-2022-4223": "pgAdmin 4 before 6.17: the validate-binary-path API runs an attacker-chosen binary, giving authenticated remote code execution.",
    "nacos/CVE-2021-29441": "Nacos 1.4.0: any request with the User-Agent Nacos-Server skips the authentication filter.",
    "tomcat/CVE-2020-1938": "Apache Tomcat 9.0.30: the AJP connector on 8009 reads files from the web root and can include them as JSP (Ghostcat).",
    "tomcat/tomcat8": "Apache Tomcat 8.0 with the manager application and a weak administrator password, so a WAR upload gives code execution.",
    "php/CVE-2012-1823": "PHP 5.4.1 in CGI mode: a query string without = is passed to php-cgi as command-line flags, giving source disclosure and code execution.",
    "uwsgi/unacc": "uWSGI 2.0.17: the uwsgi protocol port is open without authentication, so magic variables can run commands.",
    "spark/unacc": "Apache Spark standalone master: the REST submission port accepts applications without authentication, giving code execution.",
    "jetty/CVE-2021-28164": "Jetty 9.4.37: an encoded dot segment (%2e) bypasses the protection of WEB-INF and discloses its files.",
    "java/rmi-registry-bind-deserialization": "Java RMI registry 8u131: the registry accepts bind calls from remote clients and deserializes the object, giving code execution.",
    "dubbo/CVE-2019-17564": "Apache Dubbo 2.7.3: the HTTP protocol deserializes request bodies with Spring's HttpInvoker, giving remote code execution.",
    "couchdb/CVE-2022-24706": "Apache CouchDB 3.2.1: the Erlang distribution port uses the default cookie, so a remote node can run commands.",
    "hugegraph/CVE-2024-27348": "Apache HugeGraph 1.2.0: the Gremlin API allows a sandbox bypass, giving remote code execution.",
    "hertzbeat/CVE-2024-42323": "Apache HertzBeat 1.4.4: the YAML import is parsed with a vulnerable SnakeYAML, giving authenticated remote code execution.",
    "opensmtpd/CVE-2020-7247": "OpenSMTPD 6.6.1p1: an unauthenticated SMTP client can run commands through a crafted MAIL FROM.",
    "dns/dns-zone-transfer": "BIND 9.10.3 answers zone transfers (AXFR) for its zone to anyone, listing every host name.",
    "libssh/CVE-2018-10933": "libssh 0.8.1 server: a client that sends SSH2_MSG_USERAUTH_SUCCESS is treated as authenticated.",
    "openssl/CVE-2014-0160": "OpenSSL 1.0.1c: Heartbleed, a TLS heartbeat request reads up to 64 KB of server memory.",
    "grafana/admin-ssrf": "Grafana 8.5.4: a logged-in administrator can make the server request internal URLs through data source settings (SSRF).",
    "php/fpm": "PHP-FPM 7.1.3 reachable on 9000 over FastCGI: anyone can run a PHP file already on the host.",
    "php/CVE-2019-11043": "nginx with PHP-FPM 7.2.10: a crafted path with %0a corrupts FPM memory and runs commands (CVE-2019-11043).",
    "redis/4-unacc": "Redis 4.0.14 without a password: master-slave replication lets a client load a module and run commands.",
    "celery/celery3_redis_unauth": "Redis without a password used as the Celery 3 broker: a client can queue a pickle task that runs code on the worker.",
    "yapi/unacc": "YApi 1.9.2 with open registration: a user's mock script runs on the server and escapes the sandbox.",
    "xxl-job/unacc": "XXL-JOB 2.2.0: the executor on 9999 has no access token, so anyone can run commands through its REST API.",
    "nexus/CVE-2024-4956": "Nexus Repository 3 before 3.68.1: an unauthenticated path traversal returns any file the server can read.",
    "h2database/CVE-2018-10054": "Spring Boot app with the H2 web console open to all hosts (H2 before 1.4.198): the console runs SQL and a crafted JDBC URL gives code execution.",
    "supervisor/CVE-2017-11610": "Supervisor 3.3.2: the XML-RPC interface on 9001 allows an unauthenticated client to run commands.",
    "rocketmq/CVE-2023-33246": "Apache RocketMQ 5.1.0: the broker accepts configuration updates without authentication, giving remote command execution.",
    "zabbix/CVE-2017-2824": "Zabbix 3.0.3: the server's trapper port runs commands for an unauthenticated client when remote commands are enabled.",
    "n8n/CVE-2025-68613": "n8n 1.65.0: an authenticated user's workflow expression escapes the sandbox and runs code on the server.",
    "skywalking/8.3.0-sqli": "Apache SkyWalking 8.3.0: SQL injection in the GraphQL API against the embedded H2 database.",
}

CVE_RE = re.compile(r"\b(?:CVE-\d{4}-\d{4,7}|CNVD-\d{4}-\d+|WooYun-\d{4}-\d+)\b", re.I)
KEYWORDS = re.compile(r"vulnerab|allow|attacker|exploit|remote code|execute|injection|bypass|disclos|unauthenticated|deserializ|traversal|overflow|backdoor|misconfig|exposed|unauthorized|leak", re.I)


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def summary(readme):
    """The first prose sentence of the README that says what is wrong."""
    body = readme.split("\n## ", 1)[0]
    lines = [l for l in body.splitlines() if l.strip() and not l.startswith("#") and "中文" not in l and not l.strip().startswith(("-", "*", "[", "!"))]
    text = re.sub(r"\s+", " ", " ".join(lines))
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)
    sents = re.split(r"(?<=[.!?])\s+(?=[A-Z])", text)
    for s in sents:
        if KEYWORDS.search(s):
            return s.strip()
    return sents[0].strip() if sents else ""


def cves(path, readme):
    ids = CVE_RE.findall(path)
    if not ids:
        ids = CVE_RE.findall(readme[:2500])
    seen = []
    for i in ids:
        i = i.upper() if i.upper().startswith(("CVE", "CNVD")) else i
        if i not in seen:
            seen.append(i)
    return seen[:3]


def parse_port(spec):
    spec = str(spec)
    proto = "tcp"
    if "/" in spec:
        spec, proto = spec.split("/", 1)
    parts = spec.split(":")
    host, cont = (parts[-2], parts[-1]) if len(parts) >= 2 else (parts[0], parts[0])
    return int(host), int(cont), proto


def build(vulhub, pick):
    import yaml
    d = os.path.join(vulhub, pick["path"])
    comp = yaml.safe_load(read(os.path.join(d, "docker-compose.yml")))
    readme = read(os.path.join(d, "README.md"))
    services, ports = {}, []
    for name, svc in (comp.get("services") or {}).items():
        if "build" in svc:
            raise SystemExit(f"{pick['path']}: service {name} is built, not pulled")
        services[name] = {"image": svc.get("image", "")}
        for spec in svc.get("ports") or []:
            host, cont, tr = parse_port(spec)
            proto = pick.get("proto", {}).get(cont) or pick.get("proto", {}).get(host) or PORT_PROTO.get(cont) or "http"
            if proto == "http" and (cont in HTTPS_PORTS or host in HTTPS_PORTS):
                proto = "https"
            first = host == pick["primary"] and not any(q["primary"] for q in ports)
            ports.append({"service": name, "host_port": host, "container_port": cont,
                          "transport": tr, "protocol": proto, "primary": first})
    if not any(p["primary"] for p in ports):
        raise SystemExit(f"{pick['path']}: primary port {pick['primary']} is not published")
    code = pick["probe"]
    if code.startswith(("h:", "hs:")):
        scheme, path = ("https", code[3:]) if code.startswith("hs:") else ("http", code[2:])
        probe = {"kind": "http", "scheme": scheme, "port": pick["primary"], "path": path, "status_below": 500}
    else:
        probe = dict(BANNER[code])
        probe["port"] = pick["primary"]
    for p in ports:
        if p["primary"]:
            if probe["kind"] == "http":
                p["protocol"] = "https" if probe["scheme"] == "https" else "http"
    note = pick.get("note") or NOTES.get(pick["path"]) or summary(readme)
    ids = pick.get("cve") or cves(pick["path"], readme)
    return {
        "id": pick["path"].replace("/", "--"),
        "path": pick["path"],
        "product": pick["product"],
        "family": pick["family"],
        "version": pick["version"],
        "cve": ids,
        "category": pick["category"],
        "services": services,
        "ports": ports,
        "probe": probe,
        "summary": note,
        "mem_mb": pick["mem_mb"],
        "ready_s": pick["ready_s"],
        "names": pick.get("names", []),
        "proxy": bool(pick.get("proxy")),
    }


def main():
    vulhub = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "catalog.json")
    commit = subprocess.check_output(["git", "-C", vulhub, "rev-parse", "HEAD"], text=True).strip()
    seen = set()
    entries = []
    for pick in PICKS:
        if pick["path"] in seen:
            raise SystemExit("duplicate pick " + pick["path"])
        seen.add(pick["path"])
        entries.append(build(vulhub, pick))
    cat = {
        "vulhub": {"repo": "https://github.com/vulhub/vulhub", "commit": commit, "license": "MIT"},
        "categories": CATEGORIES,
        "entries": entries,
    }
    with open(out, "w", encoding="utf-8") as f:
        json.dump(cat, f, indent=1, ensure_ascii=False)
        f.write("\n")
    by = {}
    for e in entries:
        by[e["category"]] = by.get(e["category"], 0) + 1
    print(len(entries), "entries", by)


if __name__ == "__main__":
    main()
