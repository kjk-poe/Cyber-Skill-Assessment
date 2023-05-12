from urllib.request import urlopen
from bs4 import BeautifulSoup
import pandas as pd
import re
import whois
import json
import csv

def main():
    url = "https://www.secureworks.com/blog/opsec-mistakes-reveal-cobalt-mirage-threat-actors"
    page = urlopen(url)
    html = page.read().decode("utf-8")
    soup = BeautifulSoup(html, "html.parser")
    string = str(soup.get_text().replace('\n',''))

    #extract ip address
    #ip address in the url is (104 . 168 . 117 . 149), (172 . 245 . 26 . 118), (193 . 142 . 59 . 174), (185 . 208 . 77 . 164), (148 . 251 . 71 . 182.),(193.142.59.174),(172.245.26.118), (104.168.117.149)
    match = re.findall(r"[0-9]{1,3} \. [0-9]{1,3} \. [0-9]{1,3} \. [0-9]{1,3}",string)
    match_2 = re.findall(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", string)
    ip_address = match + match_2
    
    #extract hash
    line = soup.find_all("td", string=["SHA256 hash","SHA1 hash","MD5 hash"])
    hash_code = []
    for i in line:
        hash_line = i.find_previous("td")
        hash_code.append(getSubstringBetweenTwoChars(">","<",str(hash_line)))
    
    for i in range(len(hash_code)):
        if i == 0:
            #could be optimised
            first_part = hash_code[i][0:40]
            second_part = hash_code[i][len(hash_code[i])-23:len(hash_code[i])]
            hash_code[i] = first_part+second_part
        hash_code[i] = hash_code[i].replace('<br/>','')
        hash_code[i] = hash_code[i].replace(r'\n','')

    #extract domain/url
    domain_name=[]
    domain_name_line = soup.find_all("td", string=["Domain name"])
    for i in domain_name_line:
        url_line = i.find_previous("td")
        domain_name.append(getSubstringBetweenTwoChars(">","<",str(url_line)))
    
    # print(f'ip address is{ip_address}')
    # print(f'hash code is {hash_code}')
    # print(f'Domain name is {domain_name}')

    #generate whois information
    jsonfile=[]
    for i in range(len(domain_name)):
        w = (whois.whois(domain_name[i]))
        jsonfile.append(w)

    fieldnames = ['domain_name', 'registrar', 'whois_server', 'referral_url',
              'updated_date', 'creation_date', 'expiration_date', 'name_servers',
              'status', 'emails', 'dnssec', 'name', 'org', 'address', 'city',
              'state', 'registrant_postal_code', 'country']
    
    #I only output the last 3 whois infomation into a output.csv as the first whois information has different columns
    with open('output.csv',"w") as file:
        csv_file =csv.writer(file)
        csv_file.writerow(fieldnames)
        for i in range(1, len(jsonfile)):
            data= jsonfile[i]
            csv_file.writerow([data['domain_name'], data['registrar'], data['whois_server'],data['referral_url'],
                               data['updated_date'],data['creation_date'],data['expiration_date'],data['name_servers'],
                               data['status'],data['emails'],data['dnssec'],data['name'],
                               data['org'],data['address'],data['city'],data['state'],data['registrant_postal_code'],
                               data['country']])

def getSubstringBetweenTwoChars(ch1,ch2,s):
    return s[s.find(ch1)+1:s.find(ch2,len(s)-10, len(s))]

if __name__ == "__main__":
    main()