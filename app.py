import warnings
warnings.filterwarnings('ignore')

from flask import Flask, render_template, request, jsonify
from urllib.parse import urlparse, parse_qs
import requests, pickle, whois, datetime, pandas as pd, time, requests, re, urllib.request, pyshorteners, dns, ssl, \
    json, ipaddress, socket
from ipaddress import ip_address, IPv4Address, IPv6Address
from bs4 import BeautifulSoup
from ipwhois.asn import IPASN
from ipwhois.net import Net
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.preprocessing import FunctionTransformer
import numpy as np

app = Flask(__name__)

pipeline = pickle.load(open('pipeline.pkl', 'rb'))
features = pickle.load(open('features.pkl', 'rb'))


@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')


def parse(url):
    parsing = urlparse(url)
    return parsing


def fetching_domain_from_ip(parsing):
    domain = parsing.netloc
    try:
        if isinstance(ip_address(parsing.netloc), (IPv4Address, IPv6Address)):
            parsing = parsing._replace(netloc=socket.gethostbyaddr(parsing.netloc)[0].split('.', 1)[-1])
    except Exception as e:
        parsing = parsing._replace(netloc=domain[4:] if domain.startswith('www.') else domain)
    return parsing


def count_vowels(text):
    vowels = "aeiouAEIOU"
    count = 0
    for char in text:
        if char in vowels:
            count += 1
    return count


def symbols_count(url):
    symbols = ['.', '-', '_', '/', '?', '=', '@', '&', '!', ' ', '~', ',', '+', '*', '#', '$', '%']
    final_list = []
    for i in symbols:
        final_list += [len(re.findall(r'\{}'.format(i), url))]
    return final_list


def domain_in_ip(parsing):
    try:
        ip = ipaddress.ip_address(parsing.netloc)
        return 1
    except ValueError:
        return 0


def check_rendering_approach(url):
    try:
        response = requests.get(url)

        content_type = response.headers.get("Content-Type")
        x_powered_by = response.headers.get("X-Powered-By")
        script_count = 0

        soup = BeautifulSoup(response.text, "html.parser")
        for script in soup.find_all("script"):
            script_count += 1

        if content_type == "text/html":
            return 1
        else:
            return 0
    except Exception:
        return 0


import os


def get_file_name(parsing):
    file_name = os.path.basename(parsing.path)
    return file_name


def is_tld_in_params(url, parsing):
    query_params = parse_qs(parsing.query)
    for param_name, param_value in query_params.items():
        for value in param_value:
            if "." in value:
                return 1

    return 0


def measure_dns_lookup_time(url):
    try:
        response = requests.get(url)
        return response.elapsed.total_seconds()
    except BaseException:
        return 0


def check_spf(parsing):
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 6
        resolver.nameservers = ['8.8.8.8', '8.8.4.4']
        answers = resolver.resolve(parsing.netloc, 'TXT')
        for rdata in answers:
            if 'spf' in rdata.to_text():
                return 1
        return 0
    except dns.resolver.NXDOMAIN:
        return 0
    except dns.resolver.Timeout:
        return 0
    except Exception:
        return 0


def asn_ip(parsing):
    try:
        ip_address = socket.gethostbyname(parsing.netloc)
        whois_result = IPASN(Net(ip_address)).lookup()
        asn = int(whois_result['asn'])
        return asn
    except Exception as e:
        return 0


def time_domain_activation(parsing):
    try:
        w = whois.whois(parsing.netloc)
        registration_date = w.creation_date if type(w.creation_date) != list else w.creation_date[0]
        activation_time = datetime.date.today() - registration_date.date()
        return activation_time.days
    except Exception as e:
        return 0


def time_domain_expiration(parsing):
    try:
        w = whois.whois(parsing.netloc)
        registration_date = w.expiration_date
        expiration_time = registration_date.date() - datetime.date.today()
        return expiration_time.days
    except Exception as e:
        return 0


def resolved_ips(parsing):
    qty_ips = 0
    try:
        resolved_ip = set(socket.gethostbyname_ex(parsing.netloc)[-1])
        qty_ips = len(resolved_ip)
        resolved_ipv6_addresses = set()
        for info in socket.getaddrinfo(parsing.netloc, None, socket.AF_INET6):
            resolved_ipv6_addresses.add(info[4][0])
        return len(resolved_ip) + len(resolved_ipv6_addresses)
    except Exception as e:
        return qty_ips


def name_qty_servers(parsing):
    try:
        answers = dns.resolver.resolve(parsing.netloc, 'NS')
        return len([server.target for server in answers])
    except Exception as e:
        return 0

def mx_qty_servers(parsing):
    try:
        answers = dns.resolver.resolve(parsing.netloc, 'MX')
        return len([server.exchange.to_text() for server in answers])
    except Exception as e:
        return 0


def ttl_hostname(parsing):
    try:
        resolver = dns.resolver.Resolver()
        answer = resolver.resolve(parsing.netloc, 'A')
        if answer.rrset:
            return answer.rrset.ttl
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return 0
    except dns.exception.Timeout:
        return 0
    except Exception as e:
        return 0


def verify_ssl_certificate(parsing):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((parsing.hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=parsing.hostname) as ssock:
                ssock.do_handshake()
                cert = ssock.getpeercert()
                if cert:
                    return 1
                else:
                    return 0
    except Exception as e:
        return 0


def get_redirect_count(url):
    count = 0
    try:
        response = requests.head(url, allow_redirects=False)
        while response.status_code in (301, 302, 303, 307):
            url = response.headers['Location']
            count += 1
            response = requests.head(url, allow_redirects=False)
            redirect_count = count
        return count
    except BaseException:
        return 0



def url_shortened(url):
    s = pyshorteners.Shortener()
    try:
        short_url = s.tinyurl.short(url)
        if short_url:
            shortened = short_url
            if shortened:
                return 1
            else:
                return 0
        else:
            return 0
    except pyshorteners.exceptions.ShorteningErrorException:
        return 0



def extract_url_feature(parsing, url):
  test_point = {}
  l = symbols_count(url)
  test_point['qty_dot_url'] = l[0]
  test_point['qty_hyphen_url'] = l[1]
  test_point['qty_underline_url'] = l[2]
  test_point['qty_slash_url'] = l[3]
  # test_point['qty_questionmark_url'] = l[4]
  test_point['qty_equal_url'] = l[5]
  test_point['qty_at_url'] = l[6]
  # test_point['qty_and_url'] = l[7]
  # test_point['qty_exclamation_url'] = l[8]
  # test_point['qty_space_url'] = l[9]
  # test_point['qty_tilde_url'] = l[10]
  # test_point['qty_comma_url'] = l[11]
  test_point['qty_plus_url'] = l[12]
  # test_point['qty_asterisk_url'] = l[13]
  # test_point['qty_hashtag_url'] = l[14]
  # test_point['qty_dollar_url'] = l[15]
  test_point['qty_percent_url'] = l[16]

  test_point['qty_tld_url'] = len(parsing.netloc.split('.')[-1])
  test_point['length_url'] = len(url)
  return test_point

def extract_domain_feature(parsing):
  test_point = {}
  l = symbols_count(parsing.netloc)
  test_point['qty_dot_domain'] = l[0]
  test_point['qty_hyphen_domain'] = l[1]
  # test_point['qty_underline_domain'] = l[2]
  # test_point['qty_slash_domain'] = l[3]
  # test_point['qty_questionmark_domain'] = l[4]
  # test_point['qty_equal_domain'] = l[5]
  # test_point['qty_at_domain'] = l[6]
  # test_point['qty_and_domain'] = l[7]
  # test_point['qty_exclamation_domain'] = l[8]
  # test_point['qty_space_domain'] = l[9]
  # test_point['qty_tilde_domain'] = l[10]
  # test_point['qty_comma_domain'] = l[11]
  # test_point['qty_plus_domain'] = l[12]
  # test_point['qty_asterisk_domain'] = l[13]
  # test_point['qty_hashtag_domain'] = l[14]
  # test_point['qty_dollar_domain'] = l[15]
  # test_point['qty_percent_domain'] = l[16]

  test_point['qty_vowels_domain'] = count_vowels(parsing.netloc)
  test_point['domain_length'] = len(parsing.netloc)
  test_point['domain_in_ip'] = domain_in_ip(parsing)
  # test_point['server_client_domain'] = check_rendering_approach(url)
  return test_point

def extract_directory_feature(parsing):
  test_point = {}
  l = symbols_count(parsing.path)
  test_point['qty_dot_directory'] = l[0]
  test_point['qty_hyphen_directory'] = l[1]
  test_point['qty_underline_directory'] = l[2]
  test_point['qty_slash_directory'] = l[3]
  # test_point['qty_questionmark_directory'] = l[4]
  test_point['qty_equal_directory'] = l[5]
  test_point['qty_at_directory'] = l[6]
  # test_point['qty_and_directory'] = l[7]
  # test_point['qty_exclamation_directory'] = l[8]
  # test_point['qty_space_directory'] = l[9]
  # test_point['qty_tilde_directory'] = l[10]
  test_point['qty_comma_directory'] = l[11]
  test_point['qty_plus_directory'] = l[12]
  test_point['qty_asterisk_directory'] = l[13]
  # test_point['qty_hashtag_directory'] = l[14]
  # test_point['qty_dollar_directory'] = l[15]
  # test_point['qty_percent_directory'] = l[16]

  test_point['directory_length'] = len(parsing.path)
  return test_point

def extract_file_feature(parsing):
  test_point = {}
  l = symbols_count(get_file_name(parsing))
  test_point['qty_dot_file'] = l[0]
  test_point['qty_hyphen_file'] = l[1]
  test_point['qty_underline_file'] = l[2]
  # test_point['qty_slash_file'] = l[3]
  # test_point['qty_questionmark_file'] = l[4]
  # test_point['qty_equal_file'] = l[5]
  # test_point['qty_at_file'] = l[6]
  # test_point['qty_and_file'] = l[7]
  test_point['qty_exclamation_file'] = l[8]
  # test_point['qty_space_file'] = l[9]
  # test_point['qty_tilde_file'] = l[10]
  test_point['qty_comma_file'] = l[11]
  # test_point['qty_plus_file'] = l[12]
  test_point['qty_asterisk_file'] = l[13]
  # test_point['qty_hashtag_file'] = l[14]
  # test_point['qty_dollar_file'] = l[15]
  test_point['qty_percent_file'] = l[16]

  test_point['file_length'] = len(get_file_name(parsing))
  return test_point

def extract_params_feature(parsing):
  test_point = {}
  l = symbols_count(parsing.query)
  test_point['qty_dot_params'] = l[0]
  # test_point['qty_hyphen_params'] = l[1]
  test_point['qty_underline_params'] = l[2]
  # test_point['qty_slash_params'] = l[3]
  # test_point['qty_questionmark_params'] = l[4]
  # test_point['qty_equal_params'] = l[5]
  # test_point['qty_at_params'] = l[6]
  test_point['qty_and_params'] = l[7]
  # test_point['qty_exclamation_params'] = l[8]
  # test_point['qty_space_params'] = l[9]
  # test_point['qty_tilde_params'] = l[10]
  # test_point['qty_comma_params'] = l[11]
  # test_point['qty_plus_params'] = l[12]
  # test_point['qty_asterisk_params'] = l[13]
  # test_point['qty_hashtag_params'] = l[14]
  # test_point['qty_dollar_params'] = l[15]
  # test_point['qty_percent_params'] = l[16]

  test_point['params_length'] = len(parsing.query)
  test_point['tld_present_params'] = is_tld_in_params(url, parsing)
  test_point['qty_params'] = sum(len(param_values) for param_values in parse_qs(parsing.query).values())
  return test_point


feature_extraction_pipeline = FeatureUnion([
        ('url_features', FunctionTransformer(lambda x: extract_url_feature(parsing=parsing, url=url))),
        ('domain_features', FunctionTransformer(lambda x: extract_domain_feature(parsing=parsing))),
        ('directory_features', FunctionTransformer(lambda x: extract_directory_feature(parsing=parsing))),
        ('file_features', FunctionTransformer(lambda x: extract_file_feature(parsing=parsing))),
        ('params_features', FunctionTransformer(lambda x: extract_params_feature(parsing=parsing))),
        ('dns_lookup', FunctionTransformer(lambda x: measure_dns_lookup_time(url=url))),
        ('spf_checking', FunctionTransformer(lambda x: check_spf(parsing=parsing))),
        ('asn_ip', FunctionTransformer(lambda x: asn_ip(parsing=parsing))),
        ('time_domain_activation', FunctionTransformer(lambda x: time_domain_activation(parsing=parsing))),
        ('time_domain_expiration', FunctionTransformer(lambda x: time_domain_expiration(parsing=parsing))),
        ('resolved_ips', FunctionTransformer(lambda x: resolved_ips(parsing=parsing))),
        ('name_servers', FunctionTransformer(lambda x: name_qty_servers(parsing=parsing))),
        ('mx_servers', FunctionTransformer(lambda x: mx_qty_servers(parsing=parsing))),
        ('ttl_hostname', FunctionTransformer(lambda x: ttl_hostname(parsing=parsing))),
        ('verify_ssl_certificate', FunctionTransformer(lambda x: verify_ssl_certificate(parsing=parsing))),
        ('get_redirect_count', FunctionTransformer(lambda x: get_redirect_count(url=url))),
        ('url_shortened', FunctionTransformer(lambda x: url_shortened(url=url)))
    ], n_jobs=-1)


def convert_to_array(feature_union_output):
    flattened_features = []
    for feature_dict in feature_union_output[:5]:
        flattened_features.extend(list(feature_dict.values()))
    flattened_features.extend(feature_union_output[5:])
    print(len(flattened_features))
    return np.array(flattened_features)


@app.route('/url', methods=['POST'])
def get_url():
    global url
    url = request.form.get('url')
    print(f'URL IS : {url}')

    parsed_url = parse(url)
    global parsing
    parsing = fetching_domain_from_ip(parsed_url)

    extracted_features = feature_extraction_pipeline.transform(np.array([url]))
    features_list = convert_to_array(extracted_features).reshape(1, -1)
    print(features_list)
    pred = pipeline.predict(features_list)
    response_data = {'prediction': pred.tolist()}

    return jsonify(response_data)


if __name__ == '__main__':
    app.run(debug=True)
