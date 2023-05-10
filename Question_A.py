from urllib.request import urlopen
from bs4 import BeautifulSoup
import pandas as pd
import re

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
    
    print(f'ip address is{ip_address}')
    print(f'hash code is {hash_code}')
    print(f'Domain name is {domain_name}')

def getSubstringBetweenTwoChars(ch1,ch2,s):
    return s[s.find(ch1)+1:s.find(ch2,len(s)-10, len(s))]

if __name__ == "__main__":
    main()