from flask import Flask, render_template, request, jsonify
from urllib.parse import urlparse, parse_qs
import requests, pickle, whois, datetime, pandas as pd, time, requests, re, urllib.request, pyshorteners, dns, ssl, \
    json, ipaddress, socket
from ipaddress import ip_address, IPv4Address, IPv6Address
from bs4 import BeautifulSoup
from ipwhois.asn import IPASN
from ipwhois.net import Net

app = Flask(__name__)

scaler = pickle.load(open('scaler.pkl', 'rb'))
xgb = pickle.load(open('xgb.pkl', 'rb'))


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


def check_spf(domain):
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 6
        resolver.nameservers = ['8.8.8.8', '8.8.4.4']
        answers = resolver.resolve(domain, 'TXT')
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
        resolved_ips = set(socket.gethostbyname_ex(parsing.netloc)[-1])
        qty_ips = len(resolved_ips)
        resolved_ipv6_addresses = set()
        for info in socket.getaddrinfo(parsing.netloc, None, socket.AF_INET6):
            resolved_ipv6_addresses.add(info[4][0])
        return len(resolved_ips) + len(resolved_ipv6_addresses)
    except Exception as e:
        return qty_ips


def qty_servers(domain, type):
    try:
        if type == 'NS':
            answers = dns.resolver.resolve(domain, 'NS')
            return len([server.target for server in answers])
        else:
            answers = dns.resolver.resolve(domain, 'MX')
            return len([server.exchange.to_text() for server in answers])
    except Exception as e:
        return 0


def ttl_hostname(domain):
    try:
        resolver = dns.resolver.Resolver()
        answer = resolver.resolve(domain, 'A')
        if answer.rrset:
            return answer.rrset.ttl
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return 0
    except dns.exception.Timeout:
        return 0
    except Exception as e:
        return 0


def verify_ssl_certificate(hostname):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                ssock.do_handshake()
                cert = ssock.getpeercert()
                return cert
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


API_KEY = "AIzaSyBOkMJJy2D-3zH4KDz2yPkQpvC59xdVscE"
CSE_ID = "9287a0182af7e4616"


def is_url_indexed(url):
    query = f"site:{url}"
    params = {
        "key": API_KEY,
        "cx": CSE_ID,
        "q": query
    }
    response = requests.get("https://www.googleapis.com/customsearch/v1", params=params)
    data = response.json()
    if data["searchInformation"]["totalResults"] == "0":
        return 0
    else:
        return 1


def is_domain_indexed(domain):
    query = f"info:{domain}"
    params = {
        "key": API_KEY,
        "cx": CSE_ID,
        "q": query
    }
    response = requests.get("https://www.googleapis.com/customsearch/v1", params=params)
    data = response.json()
    if data["searchInformation"]["totalResults"] == "0":
        domain_indexed = 'No'
        return 0
    else:
        domain_indexed = 'Yes'
        return 1


def url_shortened(url):
    s = pyshorteners.Shortener()
    try:
        short_url = s.tinyurl.short(url)
        if short_url:
            shortened = short_url
            return shortened
        else:
            return 0
    except pyshorteners.exceptions.ShorteningErrorException:
        return 0


typos_list = ['url', 'domain', 'directory', 'file', 'params']


def assignment(parsing, url, l, typos_list):
    test_point = {}
    for i in typos_list:
        test_point['qty_dot_{}'.format(i)] = l[0]
        test_point['qty_hyphen_{}'.format(i)] = l[1]
        test_point['qty_underline_{}'.format(i)] = l[2]
        test_point['qty_slash_{}'.format(i)] = l[3]
        test_point['qty_questionmark_{}'.format(i)] = l[4]
        test_point['qty_equal_{}'.format(i)] = l[5]
        test_point['qty_at_{}'.format(i)] = l[6]
        test_point['qty_and_{}'.format(i)] = l[7]
        test_point['qty_exclamation_{}'.format(i)] = l[8]
        test_point['qty_space_{}'.format(i)] = l[9]
        test_point['qty_tilde_{}'.format(i)] = l[10]
        test_point['qty_comma_{}'.format(i)] = l[11]
        test_point['qty_plus_{}'.format(i)] = l[12]
        test_point['qty_asterisk_{}'.format(i)] = l[13]
        test_point['qty_hashtag_{}'.format(i)] = l[14]
        test_point['qty_dollar_{}'.format(i)] = l[15]
        test_point['qty_percent_{}'.format(i)] = l[16]

        if i == 'url':
            test_point['qty_tld_url'] = len(parsing.netloc.split('.')[-1])
            test_point['length_url'] = len(url)
            l = symbols_count(parsing.netloc)

        elif i == 'domain':
            test_point['qty_vowels_domain'] = count_vowels(parsing.netloc)
            test_point['domain_length'] = len(parsing.netloc)
            test_point['domain_in_ip'] = domain_in_ip(parsing)
            test_point['server_client_domain'] = check_rendering_approach(url)
            l = symbols_count(parsing.path)

        elif i == 'directory':
            test_point['{}_length'.format(i)] = len(parsing.path)
            l = symbols_count(get_file_name(parsing))

        elif i == 'file':
            test_point['{}_length'.format(i)] = len(get_file_name(parsing))
            l = symbols_count(parsing.query)

        elif i == 'params':
            test_point['{}_length'.format(i)] = len(parsing.query)
            test_point['tld_present_params'] = is_tld_in_params(url, parsing)
            test_point['qty_params'] = sum(len(param_values) for param_values in parse_qs(parsing.query).values())

    test_point['email_in_url'] = 1 if parsing.query else 0
    test_point['time_response'] = measure_dns_lookup_time(url)
    test_point['domain_spf'] = check_spf(parsing.hostname)
    test_point['asn_ip'] = asn_ip(parsing)
    test_point['time_domain_activation'] = time_domain_activation(parsing)
    test_point['time_domain_expiration'] = time_domain_expiration(parsing)
    test_point['qty_ip_resolved'] = resolved_ips(parsing)
    test_point['qty_nameservers'] = qty_servers(parsing.netloc, 'NS')
    test_point['qty_mx_servers'] = qty_servers(parsing.netloc, 'MX')
    test_point['ttl_hostname'] = ttl_hostname(parsing.netloc)
    test_point['tls_ssl_certificate'] = 1 if verify_ssl_certificate(parsing.hostname) else 0
    test_point['qty_redirects'] = get_redirect_count(url)
    test_point['url_google_index'] = is_url_indexed(url)
    test_point['domain_google_index'] = is_domain_indexed(parsing.netloc)
    test_point['url_shortened'] = 1 if url_shortened(url) else 0

    return test_point


@app.route('/url', methods=['POST'])
def get_url():
    url = request.form.get('url')
    print(f'URL IS : {url}')

    parsed_url = parse(url)
    parsing = fetching_domain_from_ip(parsed_url)

    new_test_point = assignment(parsing, url, symbols_count(url), typos_list)
    test = pd.DataFrame(new_test_point, index=[0])
    test = scaler.transform(test)
    pred = xgb.predict(test)

    response_data = {'prediction': pred.tolist()}

    return jsonify(response_data)


if __name__ == '__main__':
    app.run(debug=True)
