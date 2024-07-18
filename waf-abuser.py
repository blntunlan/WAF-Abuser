#!/usr/bin/env python3
import argparse
import asyncio
import datetime
import logging
import os
import sys
from pathlib import Path
from typing import Set

from colorama import Fore, init as colorama_init

from modules.ip_gathering import ip_gathering
from modules.subdomain_gathering import subdomain_gathering
from modules.utility import UtilityFunctions

class WAFAbuser:
    def __init__(self):
        self.logger = self._create_logger()
        self.args = self._parse_arguments()
        self.utility = UtilityFunctions()

    @staticmethod
    def _create_logger() -> logging.Logger:
        logger = logging.getLogger("WAFAbuser")
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter('{%(filename)s:%(lineno)d} | %(message)s'))
        logger.addHandler(handler)
        return logger

    @staticmethod
    def _parse_arguments() -> argparse.Namespace:
        parser = argparse.ArgumentParser(
            description='WAF-Abuser searches for unprotected IPs associated with given domains to bypass the WAF over a direct connection'
        )
        input_group = parser.add_mutually_exclusive_group(required=True)
        input_group.add_argument('-d', '--domain', dest='input_domain', metavar='"domain"',
                                 help='Specify the domain for searches')
        input_group.add_argument('-f', '--file', dest='file_domains', metavar='FILE', type=argparse.FileType('r'),
                                 help='Specify the file with domains for searches')
        parser.add_argument('--similarity-rate', type=int, default=70, metavar='[0-100]',
                            help='Specify minimum passing percentage for page similarity. Default: 70')
        parser.add_argument('--domains-only', action='store_true',
                            help='Find only domains and subdomains')
        return parser.parse_args()

    @staticmethod
    def print_banner():
        banner = f"""{Fore.MAGENTA}
        +-----------------------------+
        |╦ ╦╔═╗╔═╗  ╔═╗╔╗ ╦ ╦╔═╗╔═╗╦═╗|
        |║║║╠═╣╠╣   ╠═╣╠╩╗║ ║╚═╗║╣ ╠╦╝|
        |╚╩╝╩ ╩╚    ╩ ╩╚═╝╚═╝╚═╝╚═╝╩╚═|
        +-----------------------------+
        {Fore.RESET}"""
        print(banner)

    def get_input_domains(self) -> Set[str]:
        if self.args.file_domains:
            return {line.strip() for line in self.args.file_domains}
        return {self.args.input_domain}

    async def find_subdomains(self, input_domains: Set[str]) -> Set[str]:
        self.logger.info("1. Gathering subdomains")
        subdomains = await subdomain_gathering(input_domains)
        self.logger.debug(f"Found subdomains: {subdomains}")
        return subdomains

    async def find_ips(self, subdomains: Set[str]) -> Set[str]:
        self.logger.info("2. Gathering IPs")
        ips = await ip_gathering(subdomains)
        self.logger.debug(f"Found IPs: {ips}")
        return ips

    async def filter_ips(self, ips: Set[str]) -> Set[str]:
        self.logger.info("3. Filtering out WAF IPs")
        filtered_ips = await self.utility.filter_out_waf_ips(ips)
        self.logger.debug(f"Filtered IPs: {filtered_ips}")
        return filtered_ips

    async def compare_ips(self, input_domains: Set[str], filtered_ips: Set[str]) -> Set[tuple]:
        self.logger.info("4. Comparing found IPs with original domain")
        similarity_output = set()
        async with self.utility as util:
            for domain in input_domains:
                domain_content = await util.get_page_content(domain)
                if domain_content is None:
                    continue
                for ip in filtered_ips:
                    result = await util.compare_two_pages(domain_content, ip)
                    if result[1] > self.args.similarity_rate:
                        similarity_output.add(result)
        return similarity_output

    def output_results(self, similarity_output: Set[tuple]):
        if not similarity_output:
            self.logger.warning(f"5. Found 0 pages with similarity > {self.args.similarity_rate}%")
            self.logger.info("You can reduce the similarity percentage [--similarity_rate 70]")
            return

        self.logger.info(f"5. {Fore.GREEN}Found possible IPs:{Fore.RESET}")
        row_format = "{:>15}" * 2
        print(row_format.format("IP", "Similarity"))
        for ip, similarity in similarity_output:
            print(row_format.format(ip, f"{similarity}%"))

        output_dir = Path(__file__).parent.parent / 'output'
        output_dir.mkdir(exist_ok=True)
        output_file = output_dir / f'possible_WAF_bypass_{datetime.datetime.now():%Y%m%d_%H%M%S}.txt'
        with output_file.open('w') as f:
            f.write("\n".join(row_format.format(ip, f"{similarity}%") for ip, similarity in similarity_output))

    async def run(self):
        colorama_init()
        self.print_banner()

        input_domains = self.get_input_domains()
        subdomains = await self.find_subdomains(input_domains)

        if self.args.domains_only:
            self.logger.info(f"{Fore.GREEN}Found {len(subdomains)} domains/subdomains:{Fore.RESET}")
            for domain in subdomains:
                print(domain)
            self.logger.info(f"File output: {Path(__file__).parent.parent / 'cache'}")
            return

        ips = await self.find_ips(subdomains)
        filtered_ips = await self.filter_ips(ips)

        if not filtered_ips:
            self.logger.info(f"{Fore.GREEN}Found 0 possible non-WAF IPs{Fore.RESET}")
            return

        similarity_output = await self.compare_ips(input_domains, filtered_ips)
        self.output_results(similarity_output)

async def main():
    waf_abuser = WAFAbuser()
    await waf_abuser.run()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nProgram interrupted by user. Exiting...")
    except Exception as e:
        print(f"An error occurred: {e}")
        logging.exception("Unexpected error:")
    sys.exit(0)
