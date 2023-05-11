import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime


def main():
    df = pd.read_csv(r'.\files\http.log', delimiter='\t',  error_bad_lines=False, names=['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
                                                                                          'trans_depth', 'method','host', 'uri', 'referrer', 'user_agent',
                                                                                          'request_ body_len', 'response_ body_len', 'status_code', 'status_msg',
                                                                                          'info_code','info_msg','filename', 'tags', 'username','password','proxied',
                                                                                          'orig_fuids', 'orig_mime_types','resp_fuids','resp_mime_types'])
    #First method: Higher amount of times ip address appears, the more likely it is a reconnaissance activities acitivity
    #For this method, I will find the top 5 ip address that appear in the conn.log file.

    #get the ip_address_origin from dataframe
    ip_address_origin = df.loc[:,['ts','id.orig_h']]
    ip_address_origin['ts']=ip_address_origin['ts'].apply(lambda x: datetime.fromtimestamp(x))
    #get the count of each ip address instance
    ip_address_origin_count = ip_address_origin['id.orig_h'].value_counts()
    counts = (ip_address_origin_count[ip_address_origin_count>1000])
    ip_address_high_count = counts.index[0:5]
    print(f"ip address shortlisted by first method: {ip_address_high_count}")

    #Second method: Look for frequent connections from a single IP address to different destination ports or services
    #Reconnaissance activity often involves scanning for open ports or services on a target network or system
    #This method is done by finding the number of times an ip address is connected to a unique port. 
    #By setting a threshold, it will filter out those ip address with connections to different ports. 
    #Threshold is set randomly by me. It depends on the company on what is the threshold they want to set.
    source_ip_counts = df.groupby('id.orig_h')['id.resp_p'].nunique()
    threshold = 4
    source_ip_counts_above_threshold = source_ip_counts[source_ip_counts > threshold]
    plt.bar(source_ip_counts_above_threshold.index,source_ip_counts_above_threshold)
    plt.xlabel('ip address')
    plt.ylabel('number of unique ports')
    plt.title('Connection to different port')
    #plt.show()
    print(f"ip address shortlisted by second method: {source_ip_counts_above_threshold.index}")

    #third method: Look for multiple failed login from a single ip address. This may indicate brute force method 
    #I do not know how to search for failed login attempt through the files. 

if __name__ == "__main__":
    main()