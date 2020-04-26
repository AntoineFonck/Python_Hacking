from ipwhois import IPWhois
import socket
import requests
import re
from urllib import parse
from bs4 import BeautifulSoup
from nmap import PortScanner


class Autoscan:
    def __init__(self, host, ignore_links=[]):
        self.session = requests.Session()
        self.target_host = host
        self.target_IP = socket.gethostbyname(self.target_host)
        self.target_links = []
        self.links_to_ignore = ignore_links
        self.portscanner = PortScanner()
        self.assets_dict = {}

    def try_request(self, host=None):
        """
        :param host: host to try to request with GET
        :return: the get response if answered, none if no answer
        """
        if host is None:
            host = self.target_host
        try:
            return requests.get("http://" + host)
        except requests.exceptions.ConnectionError:
            pass

    def check_proxy(self, host=None, wordlist="./proxies.txt"):
        """
        :param host: host to be checked for known proxies
        :return: the name of the proxy if found, none otherwise
        """
        if host is None:
            host = self.target_host
        try:
            obj = IPWhois(socket.gethostbyname(host))
            with open(wordlist, "r") as wordlist_file:
                for line in wordlist_file:
                    word = line.strip()
                    if word.lower() in obj.lookup_whois().__str__().lower():
                        return word
        except:
            pass

    def check_http_redirect(self, host=None):
        """
        :param host: host to check for http redirection
        :return: the redirection url if there is one, False otherwise
        """
        if host is None:
            host = self.target_host
        response = self.try_request(host)
        if "301" in str(response.history):
            return response.url
        else:
            return False

    def find_subdomains(self, host=None, wordlist="./subdomains.txt"):
        """
        :param host: host to be checked for subdomains
        :return: the list of subdomains, none if none is found
        """
        subdomain_list = []
        if host is None:
            host = self.target_host
        with open(wordlist, "r") as wordlist_file:
            for line in wordlist_file:
                word = line.strip()
                test_url = word + "." + host
                response = self.try_request(test_url)
                if response:
                    subdomain_list.append(test_url)
        return subdomain_list

    def crawl(self, host=None, wordlist="./crawling.txt"):
        """
        :param host: host to crawl
        :return: the list of answering url, none if none is found
        """
        crawl_list = []
        if host is None:
            host = self.target_host
        with open(wordlist, "r") as wordlist_file:
            for line in wordlist_file:
                word = line.strip()
                test_url = host + "/" + word
                response = self.try_request(test_url)
                if response:
                    crawl_list.append(test_url)
        return crawl_list

    def extract_links(self, host):
        response = self.try_request(host)
        return re.findall('(?:href=")(.*?)"', str(response.content))

    def spider(self, host=None, restrict_scope=0):
        """
        :param host: host to spider
        :param restrict_scope: set to 1 to limit links scope to host, 0 otherwise
        :return: the list of found url in source code, none if none is found
        """
        if host is None:
            host = self.target_host
        href_links = self.extract_links(host)
        for link in href_links:
            full_link = parse.urljoin("http://" + host, link)

            if "#" in full_link:
                full_link = full_link.split("#")[0]

            if full_link not in self.target_links and full_link not in self.links_to_ignore:
                if restrict_scope == 1 and self.target_host in full_link:
                    self.target_links.append(full_link)
                    self.spider(full_link, restrict_scope)
                elif restrict_scope == 0:
                    self.target_links.append(full_link)
                    self.spider(full_link, restrict_scope)

    def extract_forms(self, host=None):
        """
        :param host: host from where to extract forms in HTML
        :return: all found forms, if any or found, none otherwise
        """
        if host is None:
            host = self.target_host
        response = self.session.get("http://" + host)
        parsed_html = BeautifulSoup(response.content, features="html.parser")
        return parsed_html.findAll("form")

    def sslscan(self, host=None):
        """
        :param host: host on which to perform a sslscan with nmap
        :return: raw scan result
        """
        if host is None:
            host = self.target_host
        output = self.portscanner.scan(host, "443", arguments="--script ssl-enum-ciphers")
        script_output = output["scan"][str(socket.gethostbyname(host))]["tcp"][443]['script']
        if host == self.target_host:
            self.assets_dict["SSL"] = {"TLS1.0": {"enabled": False}, "TLS1.1": {"enabled": False},
                                       "TLS1.2": {"enabled": False}, "TLS1.3": {"enabled": False}}
            if "TLSv1.0" in str(script_output):
                self.assets_dict["SSL"]["TLS1.0"]["enabled"] = True
            if "TLSv1.1" in str(script_output):
                self.assets_dict["SSL"]["TLS1.1"]["enabled"] = True
            if "TLSv1.2" in str(script_output):
                self.assets_dict["SSL"]["TLS1.2"]["enabled"] = True
            if "TLSv1.3" in str(script_output):
                self.assets_dict["SSL"]["TLS1.3"]["enabled"] = True
        return script_output
