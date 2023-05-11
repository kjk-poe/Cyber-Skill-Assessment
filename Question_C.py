import pandas as pd

def main():
    df = pd.read_csv(r'.\files\http.log', delimiter='\t',  error_bad_lines=False, names=['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
                                                                                          'trans_depth', 'method','host', 'uri', 'referrer', 'user_agent',
                                                                                          'request_ body_len', 'response_ body_len', 'status_code', 'status_msg',
                                                                                          'info_code','info_msg','filename', 'tags', 'username','password','proxied',
                                                                                          'orig_fuids', 'orig_mime_types','resp_fuids','resp_mime_types'])
    print(df)

if __name__ == "__main__":
    main()