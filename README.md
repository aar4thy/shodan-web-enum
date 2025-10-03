
# Shodan Web-App Enumeration 

## Overview
This Python GUI tool automates web application enumeration using the Shodan API. It is intended for **authorized targets only** and provides a simple interface to collect detailed information about web assets, including:

- IP and port
- Hostnames
- Organization and ISP
- Product / server
- HTTP titles
- SSL certificates
- Candidate URLs
- CVEs (vulnerabilities)


## Features
- Tkinter-based GUI for easy interaction
- Real-time progress logging and status updates
- Automatic flattening of Shodan banner data for readability
- Export results to CSV and JSON
- Deduplicates results by IP:Port


## Requirements
- Python 3.10+
- Required Python packages (install via pip)



Installation

1.Clone or extract the repository:

git clone <repo-link>

2.Install dependencies:

pip install -r requirements.txt

3.Ensure you have a Shodan API key.

Usage

1.Run the script:
python webappenum.py

2.Enter the target domain or IP.

3.Enter your Shodan API key (or ensure SHODAN_API_KEY is set in the environment).

4.Click Run Enumeration.

5.Wait for the progress bar to complete; results are displayed in a table.

6.Export the results to CSV or JSON using the buttons at the bottom.

Output

The GUI displays a flattened table of the following fields:
| Field          | Description                               |
| -------------- | ----------------------------------------- |
| IP             | IP address of the host                    |
| Port           | Service port                              |
| Hostnames      | Resolved hostnames                        |
| Org            | Organization name                         |
| ISP            | Internet Service Provider                 |
| Product        | Software product or server                |
| Version        | Product version if available              |
| HTTP Title     | Web page title                            |
| CPEs           | Common Platform Enumeration               |
| CVEs           | Known vulnerabilities                     |
| Cert_CN        | SSL certificate common name               |
| Cert_SANs      | SSL certificate subject alternative names |
| Candidate_URLs | URLs built from IPs and hostnames         |




