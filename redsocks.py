import os
import subprocess
from ..utils.utils import utils

class redsocks(object):
    def __init__(self, enable=True):
        super(redsocks, self).__init__()

        self.libutils = utils(__file__)
        self.enable = enable

        self.log_info = 'off'
        self.log_debug = 'off'
        self.log_output = self.libutils.real_path('/redsocks.log')

        self.local_ip = '127.0.0.1'
        self.local_port = '3070'

        self.ip = '127.0.0.1'
        self.port = '3080'
        self.type = 'socks5'
        self.login = ''
        self.password = ''

        self.redsocks_config = self.libutils.real_path('/redsocks.conf')

    def log(self, value):
        self.liblog.log(f'Executing: {value}', color='[P1]', type=3)

    def user_is_superuser(self):
        return True if os.getuid() == 0 else False

    def enabled(self):
         return self.enable if self.user_is_superuser() else False

    def execute(self, command):
        if not self.enabled():
            return

        self.log(command)
        os.system(command)

    def create_config(self):
        config = \
'''
base {
    log_info = {log_info};
    log_debug = {log_debug};
    log = "file:{log_output}";
    daemon = on;
    redirector = iptables;
}

redsocks {
    local_ip = {local_ip};
    local_port = {local_port};

    ip = {ip};
    port = {port};
    type = {type};
    login = "{login}";
    password = "{password}";
}

// Generated from blib_redsocks.py
// (c) 2019 Aztec Rabbit.
'''
        config = config.strip()                         \
            .replace('{log_info}', self.log_info)       \
            .replace('{log_debug}', self.log_debug)     \
            .replace('{log_output}', self.log_output)   \
                                                        \
            .replace('{local_ip}', self.local_ip)       \
            .replace('{local_port}', self.local_port)   \
                                                        \
            .replace('{ip}', self.ip)                   \
            .replace('{port}', self.port)               \
            .replace('{type}', self.type)               \
            .replace('{login}', self.login)             \
            .replace('{password}', self.password)  
        self.execute(f"echo '{config}' > {self.redsocks_config}")

    def start(self):
        commands = [
            'iptables -t nat -N REDSOCKS',
            'iptables -t nat -A REDSOCKS -d 0.0.0.0/8 -j RETURN',
            'iptables -t nat -A REDSOCKS -d 10.0.0.0/8 -j RETURN',
            'iptables -t nat -A REDSOCKS -d 127.0.0.0/8 -j RETURN',
            'iptables -t nat -A REDSOCKS -d 169.254.0.0/16 -j RETURN',
            'iptables -t nat -A REDSOCKS -d 172.16.0.0/12 -j RETURN',
            'iptables -t nat -A REDSOCKS -d 192.168.0.0/16 -j RETURN',
            'iptables -t nat -A REDSOCKS -d 224.0.0.0/4 -j RETURN',
            'iptables -t nat -A REDSOCKS -d 240.0.0.0/4 -j RETURN',
            'iptables -t nat -A REDSOCKS -p tcp -j REDIRECT --to-ports 3070',
            'iptables -t nat -A OUTPUT -p tcp -j REDSOCKS',
            'redsocks -c {}'.format(self.redsocks_config),
        ]

        self.stop()
        self.create_config()

        for command in commands:
            self.execute(command)

    def stop(self):
        commands = [
            'iptables -F',
            'iptables -X',
            'iptables -Z',
            'iptables -t nat -F',
            'iptables -t nat -X',
            'iptables -t nat -Z',
            'killall redsocks > /dev/null 2>&1',
        ]

        for command in commands:
            self.execute(command)

    def rule_direct_check(self, host):
        if not self.enabled():
            return None

        with self.liblog.lock:
            process = subprocess.Popen(f'iptables -t nat -C REDSOCKS -d {host} -j RETURN'.split(' '), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            for line in process.stdout:
                return False

            return True

    def rule_direct_insert(self, host):
        self.execute(f'iptables -t nat -I REDSOCKS -d {host} -j RETURN > /dev/null 2>&1')

    def rule_direct_update(self, host):
        result = self.rule_direct_check(host)
        if not result and result is not None:
            self.rule_direct_insert(host)