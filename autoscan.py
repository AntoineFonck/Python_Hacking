from ipwhois import IPWhois
import socket
import requests
import re
from urllib import parse
from bs4 import BeautifulSoup
from nmap import PortScanner
import pprint


class Autoscan:
    def __init__(self, host, ignore_links=[]):
        self.session = requests.Session()
        self.target_host = re.sub(r"^http://|^https://", "", host)
        self.target_IP = socket.gethostbyname(self.target_host)
        self.target_links = []
        self.crawl_links = []
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
            return requests.get("http://" + host, timeout=10)
        except requests.exceptions.ConnectionError:
            pass

    def check_proxy(self, host=None, wordlist="./wordlists/proxies.txt"):
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

    def find_subdomains(self, host=None, wordlist="./wordlists/subdomains.txt"):
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

    def crawl(self, host=None, wordlist="./wordlists/crawling.txt"):
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
        self.crawl_links = crawl_list
        return crawl_list

    def extract_links(self, host=None):
        """
        :param host: host to extract links from
        :return: list of found links if some are found
        """
        if host is None:
            host = self.target_host
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
        :return: raw script from scan result
        """
        if host is None:
            host = self.target_host
        output = self.portscanner.scan(host, "443", arguments="--script ssl-enum-ciphers")
        if "script" not in str(output['scan']):
            return None
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

    def http_header_scan(self, host=None):
        """
        :param host: host on which to perform a http header scan with nmap
        :return: raw script from scan result
        """
        if host is None:
            host = self.target_host
        output = self.portscanner.scan(host, "443", arguments="--script http-security-headers")
        if "script" not in str(output['scan']):
            return None
        script_output = output["scan"][str(socket.gethostbyname(host))]["tcp"][443]['script']
        if host == self.target_host:
            self.assets_dict["HTTP_HEADERS"] = script_output
        return script_output

    def xss_scan(self, host=None):
        """
        :param host: host on which to perform a XSS scan with nmap
        :return: raw script from scan result
        """
        if host is None:
            host = self.target_host
        output = self.portscanner.scan(host, "443", arguments="--script http-unsafe-output-escaping,http-stored-xss,"
                                                              "http-dombased-xss")
        if "script" not in str(output['scan']):
            return None
        script_output = output["scan"][str(socket.gethostbyname(host))]["tcp"][443]['script']
        if host == self.target_host:
            self.assets_dict["XSS"] = script_output
        return script_output

    def sql_scan(self, host=None):
        """
        :param host: host on which to perform a SQL scan with nmap
        :return: raw script from scan result
        """
        if host is None:
            host = self.target_host
        output = self.portscanner.scan(host, "443", arguments="--script http-sql-injection")
        if "script" not in str(output['scan']):
            return None
        script_output = output["scan"][str(socket.gethostbyname(host))]["tcp"][443]['script']
        if host == self.target_host:
            self.assets_dict["SQL"] = script_output
        return script_output

    def run(self, host=None):
        if host is None:
            host = self.target_host
        print("\t\t\tAUTOSCAN on host: " + host + "\n\n")
        proxy = self.check_proxy(host)
        if proxy is not None:
            print("[+] Found proxy: " + proxy)
        redirect = self.check_http_redirect(host)
        if redirect is not False:
            print("[+] Found redirection (from http://" + host + "): " + redirect)
        print("Trying to find subdomains ...")
        subdomain_list = self.find_subdomains(host)
        if not subdomain_list:
            print("[-] No subdomains found")
        else:
            for subdomain in subdomain_list:
                print("[+] Found: " + subdomain)
        """
        print("Crawling the website for answering URL (not recursive) ...")
        crawl_list = self.crawl(host)
        if not crawl_list:
            print("[-] No links found by crawling")
        else:
            for crawl_link in crawl_list:
                print("[+] Found: " + crawl_link)
        """
        print("Running a spider on the website to find URL (recursive) ...")
        self.spider(host)
        if not self.target_links:
            print("[-] No links found with the spider")
        else:
            for spider_link in self.target_links:
                print("[+] Found: " + spider_link)
        print("Now running several nmap scan on the website (port 443) ...")
        sslscan = self.sslscan(host)
        print("[+] SSL SCAN raw output: ")
        pprint.pprint(sslscan)
        http_header_scan = self.http_header_scan(host)
        print("[+] HTTP HEADERS SCAN raw output: ")
        pprint.pprint(http_header_scan)
        xss_scan = self.xss_scan(host)
        print("[+] XSS SCAN raw output: ")
        pprint.pprint(xss_scan)
        sql_scan = self.sql_scan(host)
        print("[+] SQL SCAN raw output: ")
        pprint.pprint(sql_scan)
