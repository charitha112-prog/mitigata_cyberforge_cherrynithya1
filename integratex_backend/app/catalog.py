"""35 connector templates. Empty endpoints/base URLs are intentional until verified
against each vendor's current API documentation and tenant-specific region/version.
"""
CONNECTORS = [
("elastic-security","Elastic Security","SIEM / Security Operations","Elastic","api_key"),
("seceon","Seceon","SIEM / Security Operations","Seceon","api_key"),
("gurucul","Gurucul","SIEM / Security Operations","Gurucul","api_key"),
("manageengine-log360","ManageEngine Log360","SIEM / Security Operations","ManageEngine","api_key"),
("logrhythm","LogRhythm","SIEM / Security Operations","LogRhythm","api_key"),
("opentext-arcsight","OpenText ArcSight","SIEM / Security Operations","OpenText","api_key"),
("binary-search","Binary Search","SIEM / Security Operations","Unverified product identity","unknown"),
("cortex-xsiam","Palo Alto Cortex XSIAM","SIEM / Security Operations","Palo Alto Networks","api_key"),
("sophos-intercept-x","Sophos Intercept X","EDR / XDR","Sophos","oauth2_client_credentials"),
("kaspersky-edr","Kaspersky EDR","EDR / XDR","Kaspersky","api_key"),
("seqrite-xdr","Seqrite XDR","EDR / XDR","Seqrite","api_key"),
("trellix-edr","Trellix EDR","EDR / XDR","Trellix","api_key"),
("trend-vision-one","Trend Micro Vision One","EDR / XDR","Trend Micro","api_key"),
("symantec-endpoint","Symantec Endpoint Security","EDR / XDR","Broadcom / Symantec","api_key"),
("forcepoint-dlp","Forcepoint DLP","Data Loss Prevention","Forcepoint","api_key"),
("symantec-dlp","Symantec DLP","Data Loss Prevention","Broadcom / Symantec","api_key"),
("digital-guardian","Digital Guardian","Data Loss Prevention","Fortra / Digital Guardian","api_key"),
("trellix-dlp","Trellix DLP","Data Loss Prevention","Trellix","api_key"),
("zscaler-dlp","Zscaler DLP","Data Loss Prevention","Zscaler","oauth2_client_credentials"),
("netskope-dlp","Netskope DLP","Data Loss Prevention","Netskope","api_key"),
("safetica","Safetica","Data Loss Prevention","Safetica","api_key"),
("fortigate","Fortinet FortiGate","Network / Firewall","Fortinet","api_key"),
("check-point","Check Point","Network / Firewall","Check Point","api_key"),
("cisco-secure-firewall","Cisco Secure Firewall","Network / Firewall","Cisco","api_key"),
("sonicwall","SonicWall","Network / Firewall","SonicWall","basic"),
("sophos-firewall","Sophos Firewall","Network / Firewall","Sophos","api_key"),
("juniper-srx","Juniper SRX","Network / Firewall","Juniper","basic"),
("watchguard-firebox","WatchGuard Firebox","Network / Firewall","WatchGuard","api_key"),
("aws-security-hub-guardduty","AWS Security Hub / GuardDuty","Cloud Security / CNAPP","Amazon Web Services","api_key"),
("google-scc","Google Security Command Center","Cloud Security / CNAPP","Google Cloud","oauth2_client_credentials"),
("wiz","Wiz","Cloud Security / CNAPP","Wiz","oauth2_client_credentials"),
("prisma-cloud","Prisma Cloud","Cloud Security / CNAPP","Palo Alto Networks","api_key"),
("orca-security","Orca Security","Cloud Security / CNAPP","Orca Security","api_key"),
("lacework-forticnapp","Lacework FortiCNAPP","Cloud Security / CNAPP","Fortinet","api_key"),
("crowdstrike-cloud-security","CrowdStrike Cloud Security","Cloud Security / CNAPP","CrowdStrike","oauth2_client_credentials")
,("github-security-advisories","GitHub Security Advisories","Vulnerability Intelligence","GitHub","none"),

("nvd-vulnerability-database","NVD Vulnerability Database","Vulnerability Intelligence","NIST","api_key"),

("jira","Jira","Incident Management","Atlassian","basic"),]


def connector_list():
    return [{"id":slug,"name":name,"category":category,"vendor":vendor,
             "availability":"template","implementation_status":"template_only",
             "auth_type":auth,"live":False,
             "base_url_required":True,"endpoints_configured":False,
             "note":"Template only. Add a verified tenant API URL, documented endpoint, credentials and permissions before testing."}
            for slug,name,category,vendor,auth in CONNECTORS]


def get_connector(slug: str):
    return next((x for x in connector_list() if x["id"]==slug),None)


def connector_template(slug: str):
    item=get_connector(slug)
    if not item: return None
    return {"name":item["name"],"vendor":item["vendor"],"base_url":"",
            "auth":{"type":item["auth_type"] if item["auth_type"]!="unknown" else "none"},
            "endpoints":[],"schedule":{"type":"manual"},"mapping":{
                "id":"id","severity":"severity","title":"title","event_time":"created_at",
                "user":"user","ip":"ip","host":"host","device_id":"device_id","resource":"resource"},
            "pagination":{"type":"none"},"incremental":{"enabled":False,"strategy":"full"}}
