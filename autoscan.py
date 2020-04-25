from ipwhois import IPWhois
import socket
import requests
import re
from urllib import parse


def check_proxy(host, wordlist="./proxies.txt"):
    """
    :param host: host to be checked for known proxies
    :return: the name of the proxy if found, none otherwise
    """
    try:
        obj = IPWhois(socket.gethostbyname(host))
        with open(wordlist, "r") as wordlist_file:
            for line in wordlist_file:
                word = line.strip()
                if word.lower() in obj.lookup_whois().__str__().lower():
                    return word
    except:
        pass


def check_http_redirect(host):
    response = try_request(host)
    if "301" in str(response.history):
        return response.url
    else:
        return False


def try_request(url):
    """
    :param url: url to try to request
    :return: the get response if answered, none if no answer
    """
    try:
        return requests.get("http://" + url)
    except requests.exceptions.ConnectionError:
        pass


def find_subdomains(host, wordlist="./subdomains.txt"):
    """
    :param host: host to be checked for subdomains
    :return: the list of subdomains, none if none is found
    """
    subdomain_list = []
    with open(wordlist, "r") as wordlist_file:
        for line in wordlist_file:
            word = line.strip()
            test_url = word + "." + host
            response = try_request(test_url)
            if response:
                subdomain_list.append(test_url)
    return subdomain_list


def crawl(host, wordlist="./crawling.txt"):
    """
    :param host: host to crawl
    :return: the list of answering url, none if none is found
    """
    crawl_list = []
    with open(wordlist, "r") as wordlist_file:
        for line in wordlist_file:
            word = line.strip()
            test_url = host + "/" + word
            response = try_request(test_url)
            if response:
                crawl_list.append(test_url)
    return crawl_list


def spider(host, restrict_scope=0):
    """
    :param host: host to spider
    :param restrict_scope: set to 1 to limit links scope to host, 0 otherwise
    :return: the list of found url in source code, none if none is found
    """
    spider_list = []
    response = try_request(host)
    href_links = re.findall('(?:href=")(.*?)"', str(response.content))
    for link in href_links:
        full_link = parse.urljoin("http://" + host, link)
        if "#" in full_link:
            full_link = full_link.split("#")[0]
        if restrict_scope == 1 and host in full_link and full_link not in spider_list:
            spider_list.append(full_link)
        elif restrict_scope == 0 and full_link not in spider_list:
            spider_list.append(full_link)
    return spider_list
