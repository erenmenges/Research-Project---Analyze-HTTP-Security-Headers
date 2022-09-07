from pandas import *
import csv
from httpobs.scanner.local import scan


## feed domains into script
data = read_csv(
    "/Users/erenmenges/Desktop/KODLAMA/VScode/Python/research/xss_dataset.csv")
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

## function to turn results into a list of zeros and ones
def process_test_results(results, site):
    listresults = []
    if results == True:
        listresults.append(3)
        return listresults
    results = results["tests"]
    if (results["x-xss-protection"]["result"] == "x-xss-protection-not-needed-due-to-csp"):
        listresults.append(0)
        return listresults
    else:
        listresults.append(1)
        return listresults

## write headers to output csv
headers = ['domain', 'xss']
with open('/Users/erenmenges/Desktop/KODLAMA/VScode/Python/research/processed_datasets/output_xss_validate.csv', 'w') as f:
    writer1 = csv.writer(f)
    writer1.writerow(headers)


## main
for site in alldomains:
    scantests = auditsite(site)
    processed_testresults = process_test_results(scantests, site)
    row = (site.split()) + processed_testresults
    with open('/Users/erenmenges/Desktop/KODLAMA/VScode/Python/research/processed_datasets/output_xss_validate.csv', 'a') as f:
        writer2 = csv.writer(f)
        writer2.writerow(row)
