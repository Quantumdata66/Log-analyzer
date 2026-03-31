# Overview #
This project is a Python based log analysis and detection tool designed to detects burst traffic, flags suspicious IPs, counts status codes, and classifies IP behavior into labeled categories.


## Features Implemented ##
1. **Log Parsing**
Reads Apache log files
Extracts:
IP address
Timestamp
HTTP request
Status code
Requested path

2. **Traffic Analysis**
Total request count
Top active IP addresses
HTTP status code distribution

3. **Detection Rules**
</High Traffic Detection>
Flags IPs with unusually high request volume

</404 Error Detection>
Detects IPs generating excessive failed requests (possible scanning or broken clients)

</Burst Detection>
Identifies IPs making >30 requests within 60 seconds
Uses time-window analysis to detect spikes in 

4. **Path Analysis**
Extracts and ranks most requested paths per IP
Helps identify:
Crawling behavior
Repeated resource access
Suspicious endpoint probing

5. **Behavioral Classification (Triage System)**

Each IP is classified into one of the following categories:

Label Description such as:
- Benign crawler	Known bots or feed-based crawling behavior
- Stale fetcher	Repeated requests to few paths (often broken or outdated clients)
- Aggressive fetcher	High activity across many paths without clear malicious intent
- Aggressive bot	Suspicious probing (e.g., admin/login endpoints)
- Needs investigation	Unclear behavior requiring further analysis>

**Classification is based on the following:**
- request volume
- path diversity
- error rates
- burst activity
- request patterns

## Scope of Phase 1 ##
This phase is rule based and does not use any machine learning.

It focuses on:
- understanding data
- identifying meaningful signals
- building detection intuition


### **Next Phase** ###
Phase 2 – Data Structuring & Analysis
Export logs to structured format (CSV/SQL)
Perform deeper analysis using SQL/Pandas
Build dashboards for visualization