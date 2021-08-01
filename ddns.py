import logging
import sys
import os
import configparser

import requests
import dns.resolver

from functools import wraps

logger = logging.getLogger('__name__')
logging.basicConfig(level = logging.INFO, format = '%(asctime)s [%(levelname)s] %(message)s')

def debug_log(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        logger.debug(f"[Started] '{ func.__name__}' with {args} and {kwargs}")
        ret = func(*args, **kwargs)
        logger.debug(f"[Ended] '{ func.__name__}' return {ret}")
        return ret
    return wrapper

@debug_log
def getLocalPublicIP():
    try:
        r = requests.get('https://ip.hlz.ink', timeout=2)
        return r.text;
    except requests.exceptions.RequestException:
        logger.exception('Faild on Requesting Local Public Address')
        sys.exit(1)

@debug_log
def getDomainResolve(host, dns_server):
    try:
        dnspod_resolver = dns.resolver.Resolver(configure=False)
        dnspod_resolver.nameservers = [dns_server]
        r = dnspod_resolver.query(host,'A')
        for rdata in r.rrset:
            if rdata.rdtype == 1:
                return rdata.address
    except dns.exception.DNSException:
        logger.exception('Faild on Resolve Domain: ' + host)
        sys.exit(1)

@debug_log
def readConfig(file_path, section_name):
    try:
        config = configparser.ConfigParser()
        config.read(file_path, encoding='utf-8')
        return dict(config.items(section_name))
    except configparser.Error:
        logger.exception(f'Faild on Reading Config: {file_path} - [{section_name}]')
        sys.exit(1)

class DNSPOD_DDNS:
    dns_server = '119.29.29.29'

    @staticmethod
    @debug_log
    def post(url, data, sus_info, fail_info):
        try:
            headers = {'User-Agent': 'HLZ DDNS-DNSPOD Client/0.1'}
            r = requests.post(
                url=url,
                data=data,
                headers=headers,
                timeout=2
            )
            r = r.json()
            if r['status']['code'] == '1':
                logger.info(sus_info)
                return r
            else:
                raise requests.exceptions.RequestException(r)
        except requests.exceptions.RequestException:
            logger.exception(fail_info)
            sys.exit(1)

    @staticmethod
    @debug_log
    def configDNSPOD(config_name):
        config = configparser.ConfigParser()
        if os.path.exists('dnspod_config.ini'):
            config.read('dnspod_config.ini', encoding='utf-8')
        logger.info('Creating DNSPOD Config - ' + config_name)

        tmp = {}
        tmp['dnspod_id'] = input('dnspod id: ')
        tmp['dnspod_token'] = input('dnspod token: ')
        tmp['domain'] = input('domain: ')
        tmp['sub_domain'] = input('sub domain: ')
        tmp['domain_id'] = input('domian id: ')
        print(f'Is this ok? \n {config_name} - {tmp}')
        is_continue = input('[Yes]/No: ')
        if is_continue == 'No' or is_continue == 'n' or is_continue == 'no':
            sys.exit(0)

        data = {
            'login_token': tmp['dnspod_id'] + ',' + tmp['dnspod_token'],
            'format': 'json',
            'domain_id' : tmp['domain_id'],
            'sub_domain': tmp['sub_domain']
        }
        r = DNSPOD_DDNS.post(
            'https://dnsapi.cn/Record.List',
            data,
            'Successfully get sub domain id',
            'Failed on getting sub domain id'
        )
        tmp['sub_domain_id'] = r['records'][0]['id']

        config.read_dict({config_name: tmp})
        config.write(open('dnspod_config.ini', 'w'))
        logger.info('Successfully Created Config - ' + config_name)

    @debug_log
    def __init__(self, config):
        self.config = config
        self.sub_domain = config['sub_domain']
        self.domain = config['domain']
        self.host = f'{self.sub_domain}.{self.domain}'
        self.dnspod_id = config['dnspod_id']
        self.dnspod_token = config['dnspod_token']
        self.domain_id = config['dnspod_domain_id']
        self.sub_domain_id = config['dnspod_subdomain_id']

    @debug_log
    def detectChange(self):
        hr = getLocalPublicIP()
        dr = getDomainResolve(self.host, self.dns_server)
        if hr == dr:
            logger.info(f'Record of {self.host} is same with Local Address')
            return (False, hr)
        else:
            logger.info(f'Record of {self.host} is different from Local Address')
            return (True, hr)

    @debug_log
    def changeRecord(self, target):
        data = {
                'login_token': self.dnspod_id + ',' + self.dnspod_token,
                'format': 'json',
                'domain_id': self.domain_id,
                'record_id': self.sub_domain_id,
                'sub_domain': self.sub_domain,
                'record_line': '默认',
                'record_type': 'A',
                'value': target
            }
        DNSPOD_DDNS.post(
            'https://dnsapi.cn/Record.Modify',
            data,
            f'Successfully Changed {self.host} to {target}',
            'Faild on Changing the record of ' + self.host
        )

    @debug_log
    def check(self):
        isChanged, target = self.detectChange()
        if isChanged:
            self.changeRecord(target)

if __name__ == '__main__':
    
    if '--help' in sys.argv or len(sys.argv) == 1:
        print(
'''
HLZ's DDNS Script
Currently only support DNSPOD(tencent-cloud)

ddns.py [Operator] <Config_name>

Operator:
    --debug     Enable Debug Mode
    --help      Print this help
    --config    Create a new config

Config_name:
    Indicate a specifc configuration in the config file (./dnspod_config.ini)
'''
        )
        sys.exit(0)

    config = sys.argv[1]
    for arg in sys.argv:
        if '--' in arg:
            continue
        else:
            config = arg

    if '--debug' in sys.argv:
        logger.setLevel(logging.DEBUG)

    if '--config' in sys.argv:
        DNSPOD_DDNS.configDNSPOD(config)
        sys.exit(0)
    
    config = readConfig('dnspod_config.ini', config)
    DNSPOD_DDNS(config).check()