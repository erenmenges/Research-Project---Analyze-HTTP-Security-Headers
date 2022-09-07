from pandas import *
import csv
import socket
from httpobs.scanner.local import scan


## feed domains into script
data = read_csv(
    "/Users/erenmenges/Desktop/KODLAMA/VScode/Python/research/raw datasets/current-nonfederal.csv")
alldomains = data['Domain Name'].tolist()


## function to scan site for HTTP security headers
def auditsite(host):
    try:
        scan_raw = scan(host)
        if (scan_raw["error"] == "site down"):
            down = True
            return down
    except KeyError:
        return scan_raw

def redirectcheck(domain, response):
    try:
        link_string = response["scan"]["response_headers"]["link"]
        if domain in link_string:
            return False
        else:
            redirection_destination = response["tests"]["redirection"]["destination"]
            if redirection_destination == None:
                return 5
            else:
                if domain in redirection_destination:
                    return False
                else:
                    return True
    except KeyError:
        redirection_destination = response["tests"]["redirection"]["destination"]
        if redirection_destination == None:
            return 5
        else:
            if domain in redirection_destination:
                return False
            else:
                return True
        


## function to turn results into a list of zeros and ones
def process_test_results(results, site):
    listresults = []
    if (results == True):
        listresults.extend([2,2,2,2,2,2,2,2,2,2,2,2])
        return listresults
    if redirectcheck(site, results) == True:
        listresults.extend([2,2,2,2,2,2,2,2,2,2,2,2])
        return listresults
    if redirectcheck(site, results) == 5:
        results = results["tests"]
        for test_name, values in results.items():
            if (values["pass"]):
                listresults.append(1)
            else:
                listresults.append(0)
        listresults.append(3)
        return listresults
    results = results["tests"]
    for test_name, values in results.items():
        if (values["pass"]):
            listresults.append(1)
        else:
            listresults.append(0)
    return listresults

## function to check if host is accessible
def urlcheck(host):
    try:
        socket.gethostbyname(host)
    except socket.gaierror:
        return False
    else:
        return True

## write headers to output csv
headers = ['domain', 'content-security-policy', 'contribute', 'cookies', 'cross-origin-resource-sharing', 'public-key-pinning', 'redirection',
           'referrer-policy', 'strict-transport-security', 'subresource-integrity', 'x-content-type-options', 'x-frame-options', 'x-xss-protection', 'known-redirection']
with open('/Users/erenmenges/Desktop/KODLAMA/VScode/Python/research/processed_datasets/outputw2_nonfederal1.csv', 'w') as f:
    writer1 = csv.writer(f)
    writer1.writerow(headers)

## lowercase all domains
for i in range(len(alldomains)):
    alldomains[i] = alldomains[i].lower()

## filter offline domains and put online ones to another list
online_domains_list = []
for site in alldomains:
    if urlcheck(site) == True:
        online_domains_list.append(site)

## create online domains csv
online_headers = ["Domain Name"]
with open('/Users/erenmenges/Desktop/KODLAMA/VScode/Python/online_nonfederal1.csv', 'w') as f:
    writer4 = csv.writer(f)
    writer4.writerow(online_headers)

## write online domains to the csv
for site in online_domains_list:
    with open('/Users/erenmenges/Desktop/KODLAMA/VScode/Python/online_nonfederal1.csv', 'a') as f:
        writer5 = csv.writer(f)
        writer5.writerow(site.split())

## read online domains from csv to a list
online_data = read_csv(
    "/Users/erenmenges/Desktop/KODLAMA/VScode/Python/online_nonfederal1.csv")
online_domains = online_data['Domain Name'].tolist()


## main
for site in online_domains:
    scantests = auditsite(site)
    processed_testresults = process_test_results(scantests, site)
    row = (site.split()) + processed_testresults
    with open('/Users/erenmenges/Desktop/KODLAMA/VScode/Python/research/processed_datasets/outputw2_nonfederal1.csv', 'a') as f:
        writer2 = csv.writer(f)
        writer2.writerow(row)
