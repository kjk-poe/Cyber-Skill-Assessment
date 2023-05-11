import pandas as pd

def main():
    df = pd.read_csv(r'.\files\http.log', delimiter='\t',  error_bad_lines=False, names=['Date/time', 'hash/identity', 'ip_address_1', 'userid/identity', 'ip_address_2', 'timezone', 'method', 'ip_address_3','request_url', 'something1', 'something2', 'something3','something4', 'status code', 'something5', 'something6', 'something7','something8','something9', 'something10', 'something11','something12','something13', 'something14', 'something15','something16','something17'])
    print(df)

if __name__ == "__main__":
    main()