# -*- coding: utf-8 -*-
""" ==========================================================
File:        WakaTime.py
Description: Automatic time tracking for IDA Pro.
Maintainer:  Arsenii Esenin <me@es3n.in>
License:     MIT, see LICENSE for more details.
Website:     https://github.com/es3n1n/ida-wakatime-py
==========================================================="""

import json
import os
import platform
import re
import shutil
import ssl
import subprocess
import sys
import threading
import time
import traceback
import webbrowser
import zlib
from subprocess import PIPE
from subprocess import STDOUT
from zipfile import ZipFile

import idaapi
import idc
from ida_kernwin import ask_buttons
from ida_kernwin import ask_str

try:
    import Queue as queue  # py2  # noqa
except ImportError:
    import queue  # py3

try:  # @note: @es3n1n: py2
    from ConfigParser import SafeConfigParser as ConfigParser  # noqa
    from ConfigParser import Error as ConfigParserError  # noqa
except ImportError:  # @note: @es3n1n: py3
    from configparser import ConfigParser  # noqa
    from configparser import Error as ConfigParserError  # noqa

try:  # @note: @es3n1n: py2
    from urllib2 import Request  # noqa
    from urllib2 import urlopen  # noqa
    from urllib2 import HTTPError  # noqa
except ImportError:  # @note: @es3n1n: py3
    from urllib.request import Request  # noqa
    from urllib.request import urlopen  # noqa
    from urllib.error import HTTPError  # noqa

# @note: @es3n1n: init py2-py3 stuff
is_py2 = (sys.version_info[0] == 2)
is_py3 = (sys.version_info[0] == 3)

# @note: @es3n1n: plugin-related stuff
VERSION = "1.0"
NETNODE_NAME = "$ WakaTime"

# @note: @es3n1n: netnode-related stuff
BLOB_SIZE = 1024
STR_KEYS_TAG = 'N'
STR_TO_INT_MAP_TAG = 'O'

# @note: @es3n1n: ida-related stuff
ida_ver = idaapi.get_kernel_version()
ida_major, ida_minor = list(map(int, ida_ver.split(".")))
using_ida7api = (ida_major > 6)

# @note: @es3n1n: Log Levels
DEBUG = 'DEBUG'
INFO = 'INFO'
WARNING = 'WARNING'
ERROR = 'ERROR'

# @note: @es3n1n: wakatime stuff
IS_WIN = platform.system() == 'Windows'
HOME_FOLDER = os.path.realpath(
    os.environ.get('WAKATIME_HOME') or os.path.expanduser('~')
)
RESOURCES_FOLDER = os.path.join(HOME_FOLDER, '.wakatime')
CONFIG_FILE = os.path.join(HOME_FOLDER, '.wakatime.cfg')
INTERNAL_CONFIG_FILE = os.path.join(HOME_FOLDER, '.wakatime-internal.cfg')
GITHUB_RELEASES_STABLE_URL = 'https://api.github.com/repos/wakatime/wakatime' \
                             '-cli/releases/latest'
GITHUB_DOWNLOAD_PREFIX = 'https://github.com/wakatime/wakatime-cli/releases' \
                         '/download'
LAST_HEARTBEAT = {
    'time': 0,
    'file': None,
    'is_write': False,
}
LAST_HEARTBEAT_SENT_AT = 0
LAST_FETCH_TODAY_CODING_TIME = 0
FETCH_TODAY_DEBOUNCE_COUNTER = 0
FETCH_TODAY_DEBOUNCE_SECONDS = 60
LATEST_CLI_VERSION = None
WAKATIME_CLI_VERSION = None
WAKATIME_CLI_LOCATION = None
HEARTBEATS = queue.Queue()
HEARTBEAT_FREQUENCY = 2  # minutes between logging heartbeat when editing file
SEND_BUFFER_SECONDS = 30  # seconds between sending buffered heartbeats to API


# @credits: https://github.com/williballenthin/ida-netnode
class NetnodeCorruptError(RuntimeError):
    pass


class Netnode(object):
    def __init__(self, netnode_name):
        self._netnode_name = netnode_name
        # self._n = idaapi.netnode(netnode_name, namelen=0, do_create=True)
        self._n = idaapi.netnode(netnode_name, 0, True)

    @staticmethod
    def _decompress(data):
        """
        args:
          data (bytes): the data to decompress
        returns:
          bytes: the decompressed data.
        """
        return zlib.decompress(data)

    @staticmethod
    def _compress(data):
        """
        args:
          data (bytes): the data to compress
        returns:
          bytes: the compressed data.
        """
        return zlib.compress(data)

    @staticmethod
    def _encode(data):
        """
        args:
          data (object): the data to serialize to json.
        returns:
          bytes: the ascii-encoded serialized data buffer.
        """
        return json.dumps(data).encode("ascii")

    @staticmethod
    def _decode(data):
        """
        args:
          data (bytes): the ascii-encoded json serialized data buffer.
        returns:
          object: the deserialized object.
        """
        return json.loads(data.decode("ascii"))

    def _get_next_slot(self, tag):
        """
        get the first unused supval table key, or 0 if the
         table is empty.
        useful for filling the supval table sequentially.
        """
        slot = self._n.suplast(tag)
        if slot is None or slot == idaapi.BADNODE:
            return 0
        else:
            return slot + 1

    def _strdel(self, key):
        assert isinstance(key, str)

        did_del = False
        storekey = self._n.hashval(key, STR_TO_INT_MAP_TAG)
        if storekey is not None:
            storekey = int(storekey.decode('utf-8'))
            self._n.delblob(storekey, STR_KEYS_TAG)
            self._n.hashdel(key, STR_TO_INT_MAP_TAG)
            did_del = True
        if self._n.hashval(key):
            self._n.hashdel(key)
            did_del = True

        if not did_del:
            raise KeyError("'{}' not found".format(key))

    def _strset(self, key, value):
        assert isinstance(key, str)
        assert value is not None

        try:
            self._strdel(key)
        except KeyError:
            pass

        if len(value) > BLOB_SIZE:
            storekey = self._get_next_slot(STR_KEYS_TAG)
            self._n.setblob(value, storekey, STR_KEYS_TAG)
            self._n.hashset(key, str(storekey).encode('utf-8'),
                            STR_TO_INT_MAP_TAG)
        else:
            self._n.hashset(key, bytes(value))

    def _strget(self, key):
        assert isinstance(key, str)

        storekey = self._n.hashval(key, STR_TO_INT_MAP_TAG)
        if storekey is not None:
            storekey = int(storekey.decode('utf-8'))
            v = self._n.getblob(storekey, STR_KEYS_TAG)
            if v is None:
                raise NetnodeCorruptError()
            return v

        v = self._n.hashval(key)
        if v is not None:
            return v

        raise KeyError("'{}' not found".format(key))

    def __getitem__(self, key):
        if isinstance(key, str):
            v = self._strget(key)
        else:
            raise TypeError("cannot use {} as key".format(type(key)))

        data = self._decompress(v)
        return self._decode(data)

    def __setitem__(self, key, value):
        """
        does not support setting a value to None.
        value must be json-serializable.
        key must be a string or integer.
        """
        assert value is not None

        v = self._compress(self._encode(value))
        if isinstance(key, str):
            self._strset(key, v)
        else:
            raise TypeError("cannot use {} as key".format(type(key)))

    def __delitem__(self, key):
        if isinstance(key, str):
            self._strdel(key)
        else:
            raise TypeError("cannot use {} as key".format(type(key)))

    def get(self, key, default=None):
        try:
            return self[key]
        except (KeyError, zlib.error):
            return default

    def __contains__(self, key):
        try:
            if self[key] is not None:
                return True
            return False
        except (KeyError, zlib.error):
            return False

    def _iter_str_keys_small(self):
        # string keys for all small values
        if using_ida7api:
            i = self._n.hashfirst()
        else:
            i = self._n.hash1st()  # noqa
        while i != idaapi.BADNODE and i is not None:
            yield i
            if using_ida7api:
                i = self._n.hashnext(i)
            else:
                i = self._n.hashnxt(i)  # noqa

    def _iter_str_keys_large(self):
        # string keys for all big values
        if using_ida7api:
            i = self._n.hashfirst(STR_TO_INT_MAP_TAG)
        else:
            i = self._n.hash1st(STR_TO_INT_MAP_TAG)  # noqa
        while i != idaapi.BADNODE and i is not None:
            yield i
            if using_ida7api:
                i = self._n.hashnext(i, STR_TO_INT_MAP_TAG)
            else:
                i = self._n.hashnxt(i, STR_TO_INT_MAP_TAG)  # noqa

    def iterkeys(self):
        for key in self._iter_str_keys_small():
            yield key

        for key in self._iter_str_keys_large():
            yield key

    def keys(self):
        return [k for k in list(self.iterkeys())]

    def itervalues(self):
        for k in list(self.keys()):
            yield self[k]

    def values(self):
        return [v for v in list(self.itervalues())]

    def iteritems(self):
        for k in list(self.keys()):
            yield k, self[k]

    def items(self):
        return [(k, v) for k, v in list(self.iteritems())]

    def kill(self):
        self._n.kill()
        self._n = idaapi.netnode(self._netnode_name, 0, True)


# @note: @es3n1n: Initializing global netnode for config
NETNODE = Netnode(NETNODE_NAME)


# @note: @es3n1n: Utils
class Popen(subprocess.Popen):
    """Patched Popen to prevent opening cmd window on Windows platform."""

    def __init__(self, *args, **kwargs):
        if IS_WIN:
            startupinfo = kwargs.get('startupinfo')
            try:
                startupinfo = startupinfo or subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            except AttributeError:
                pass
            kwargs['startupinfo'] = startupinfo
        super(Popen, self).__init__(*args, **kwargs)


def log(lvl, message, *args, **kwargs):
    if lvl == DEBUG and NETNODE.get('debug', 'false') == 'false':
        return

    msg = message

    if len(args) > 0:
        msg = message.format(*args)
    elif len(kwargs) > 0:
        msg = message.format(**kwargs)

    print('WakaTime > {lvl} > {msg}'.format(lvl=lvl, msg=msg))


def parse_config_file(config_file):
    """Returns a configparser.SafeConfigParser instance with configs
    read from the config file. Default location of the config file is
    at ~/.wakatime.cfg.
    """

    kwargs = {} if is_py2 else {'strict': False}
    configs = ConfigParser(**kwargs)
    try:
        with open(config_file, 'r', encoding='utf-8') as fh:
            try:
                if is_py2:
                    configs.readfp(fh)  # noqa
                else:
                    configs.read_file(fh)
                return configs
            except ConfigParserError:
                log(ERROR, traceback.format_exc())
                return None
    except IOError:
        return


def last_modified_and_versions(configs):
    last_modified, last_version = None, None
    if configs.has_option('internal', 'cli_version'):
        last_version = configs.get('internal', 'cli_version')
    if last_version and configs.has_option('internal',
                                           'cli_version_last_modified'):
        last_modified = configs.get('internal', 'cli_version_last_modified')
    if last_modified and last_version and extract_version(last_version):
        return last_modified, last_version
    return None, None


def extract_version(text):
    pattern = re.compile(r"([0-9]+\.[0-9]+\.[0-9]+)")
    match = pattern.search(text)
    if match:
        return 'v{ver}'.format(ver=match.group(1))
    return None


def request(url, last_modified=None):
    req = Request(url)

    if last_modified:
        req.add_header('If-Modified-Since', last_modified)

    try:
        resp = urlopen(req)
        headers = dict(resp.getheaders()) if is_py2 else resp.headers
        return headers, resp.read(), resp.getcode()
    except HTTPError as err:
        if err.code == 304:
            return None, None, 304
        if is_py2:
            with SSLCertVerificationDisabled():
                try:
                    resp = urlopen(req)
                    headers = dict(
                        resp.getheaders()) if is_py2 else resp.headers
                    return headers, resp.read(), resp.getcode()
                except HTTPError as err2:
                    if err2.code == 304:
                        return None, None, 304
                    log(ERROR, err.read().decode())
                    log(ERROR, err2.read().decode())
                    raise
                except IOError:
                    raise
        log(ERROR, err.read().decode())
        raise
    except IOError:
        if is_py2:
            with SSLCertVerificationDisabled():
                try:
                    resp = urlopen(url)
                    headers = dict(
                        resp.getheaders()) if is_py2 else resp.headers
                    return headers, resp.read(), resp.getcode()
                except HTTPError as err:
                    if err.code == 304:
                        return None, None, 304
                    log(ERROR, err.read().decode())
                    raise
                except IOError:
                    raise
        raise


def download(url, file_path):
    req = Request(url)

    with open(file_path, 'wb') as fh:
        try:
            resp = urlopen(req)
            fh.write(resp.read())
        except HTTPError as err:
            if err.code == 304:
                return None, None, 304
            if is_py2:
                with SSLCertVerificationDisabled():
                    try:
                        resp = urlopen(req)
                        fh.write(resp.read())
                        return
                    except HTTPError as err2:
                        log(ERROR, err.read().decode())
                        log(ERROR, err2.read().decode())
                        raise
                    except IOError:
                        raise
            log(ERROR, err.read().decode())
            raise
        except IOError:
            if is_py2:
                with SSLCertVerificationDisabled():
                    try:
                        resp = urlopen(url)
                        fh.write(resp.read())
                        return
                    except HTTPError as err:
                        log(ERROR, err.read().decode())
                        raise
                    except IOError:
                        raise
            raise


def is_symlink(path):
    try:
        return os.is_symlink(path)  # noqa
    except:  # noqa
        return False


def get_cli_location():
    global WAKATIME_CLI_LOCATION

    if not WAKATIME_CLI_LOCATION:
        binary = 'wakatime-cli-{osname}-{arch}{ext}'.format(
            osname=platform.system().lower(),
            arch=architecture(),
            ext='.exe' if IS_WIN else '',
        )
        WAKATIME_CLI_LOCATION = os.path.join(RESOURCES_FOLDER, binary)

    return WAKATIME_CLI_LOCATION


def create_symlink():
    link = os.path.join(RESOURCES_FOLDER, 'wakatime-cli')
    if IS_WIN:
        link = link + '.exe'
    elif os.path.exists(link) and is_symlink(link):
        return  # don't re-create symlink on Unix-like platforms

    try:
        os.symlink(get_cli_location(), link)
    except:  # noqa
        try:
            shutil.copy2(get_cli_location(), link)
            if not IS_WIN:
                os.chmod(link, 509)  # 755
        except:  # noqa
            log(ERROR, traceback.format_exc())


class SSLCertVerificationDisabled(object):

    def __enter__(self):
        self.original_context = ssl._create_default_https_context  # noqa
        ssl._create_default_https_context = ssl._create_unverified_context  # noqa

    def __exit__(self, *args, **kwargs):
        ssl._create_default_https_context = self.original_context


def get_latest_cli_version():
    global LATEST_CLI_VERSION

    if LATEST_CLI_VERSION:
        return LATEST_CLI_VERSION

    configs, last_modified, last_version = None, None, None
    try:
        configs = parse_config_file(INTERNAL_CONFIG_FILE)
        if configs:
            last_modified, last_version = last_modified_and_versions(configs)
    except:  # noqa
        log(DEBUG, traceback.format_exc())

    try:
        headers, contents, code = request(GITHUB_RELEASES_STABLE_URL,
                                          last_modified=last_modified)

        if code == 304:
            LATEST_CLI_VERSION = last_version
            return last_version

        data = json.loads(contents.decode('utf-8'))

        ver = data['tag_name']

        if configs:
            last_modified = headers.get('Last-Modified')
            if not configs.has_section('internal'):
                configs.add_section('internal')
            configs.set('internal', 'cli_version', ver)
            configs.set('internal', 'cli_version_last_modified', last_modified)
            with open(INTERNAL_CONFIG_FILE, 'w', encoding='utf-8') as fh:
                configs.write(fh)

        LATEST_CLI_VERSION = ver
        return ver
    except:  # noqa
        log(ERROR, traceback.format_exc())
        return None


def cli_download_url():
    return '{prefix}/{version}/wakatime-cli-{osname}-{arch}.zip'.format(
        prefix=GITHUB_DOWNLOAD_PREFIX,
        version=get_latest_cli_version(),
        osname=platform.system().lower(),
        arch=architecture(),
    )


class DownloadCLI(threading.Thread):

    def run(self):
        log(INFO, 'Downloading wakatime-cli...')

        if os.path.isdir(os.path.join(RESOURCES_FOLDER, 'wakatime-cli')):
            shutil.rmtree(os.path.join(RESOURCES_FOLDER, 'wakatime-cli'))

        if not os.path.exists(RESOURCES_FOLDER):
            os.makedirs(RESOURCES_FOLDER)

        try:
            url = cli_download_url()
            log(INFO, 'Downloading wakatime-cli from {url}'.format(url=url))
            zip_file = os.path.join(RESOURCES_FOLDER, 'wakatime-cli.zip')
            download(url, zip_file)

            if is_cli_installed():
                try:
                    os.remove(get_cli_location())
                except:  # noqa
                    log(DEBUG, traceback.format_exc())

            log(INFO, 'Extracting wakatime-cli...')
            with ZipFile(zip_file) as zf:
                zf.extractall(RESOURCES_FOLDER)

            if not IS_WIN:
                os.chmod(get_cli_location(), 509)  # 755

            try:
                os.remove(os.path.join(RESOURCES_FOLDER, 'wakatime-cli.zip'))
            except:  # noqa
                log(ERROR, traceback.format_exc())
        except:  # noqa
            log(ERROR, traceback.format_exc())

        create_symlink()

        log(INFO, 'Finished extracting wakatime-cli.')


def architecture():
    arch = platform.machine() or platform.processor()
    if arch == 'armv7l':
        return 'arm'
    if arch == 'aarch64':
        return 'arm64'
    if 'arm' in arch:
        return 'arm64' if sys.maxsize > 2 ** 32 else 'arm'
    return 'amd64' if sys.maxsize > 2 ** 32 else '386'


def is_cli_installed():
    return os.path.exists(get_cli_location())


def is_cli_latest():
    global WAKATIME_CLI_VERSION

    if not is_cli_installed():
        return False

    args = [get_cli_location(), '--version']
    try:
        stdout, stderr = Popen(args, stdout=PIPE, stderr=PIPE).communicate()
    except:  # noqa
        return False
    stdout = (stdout or b'') + (stderr or b'')
    local_ver = extract_version(stdout.decode('utf-8'))
    if not local_ver:
        log(WARNING, 'Local wakatime-cli version not found.')
        return False

    WAKATIME_CLI_VERSION = local_ver

    remote_ver = get_latest_cli_version()

    if not remote_ver:
        return True

    if remote_ver == local_ver:
        return True

    log(INFO, 'Found an updated wakatime-cli %s' % remote_ver)
    return False


def obfuscate_apikey(command_list):
    cmd = list(command_list)
    apikey_index = None
    for num in range(len(cmd)):
        if cmd[num] == '--key':
            apikey_index = num + 1
            break
    if apikey_index is not None and apikey_index < len(cmd):
        v = cmd[apikey_index][-4:]
        cmd[apikey_index] = 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXX' + v
    return cmd


def enough_time_passed(now, is_write):
    if now - LAST_HEARTBEAT['time'] > HEARTBEAT_FREQUENCY * 60:
        return True
    if is_write and now - LAST_HEARTBEAT['time'] > 2:
        return True
    return False


class ApiKey(object):
    _key = None

    def read(self):
        if self._key:
            return self._key

        key = NETNODE.get('api_key')
        if key:
            self._key = key
            return self._key

        try:
            configs = parse_config_file(CONFIG_FILE)
            if configs:
                if configs.has_option('settings', 'api_key'):
                    key = configs.get('settings', 'api_key')
                    if key:
                        self._key = key
                        return self._key
        except:  # noqa
            pass

        return self._key

    def write(self, key):
        global NETNODE
        self._key = key
        NETNODE['api_key'] = str(key)


APIKEY = ApiKey()


def build_heartbeat(entity=None, timestamp=None, is_write=None,
                    project=None, idb_path=None):
    """Returns a dict for passing to wakatime-cli as arguments."""

    heartbeat = {
        'entity': entity,
        'timestamp': timestamp,
        'is_write': is_write,
        'idb_path': idb_path
    }

    if project:
        heartbeat['alternate_project'] = project

    return heartbeat


class SendHeartbeatsThread(threading.Thread):
    """Non-blocking thread for sending heartbeats to api.
    """

    def __init__(self, heartbeat):
        threading.Thread.__init__(self)

        self.extra_heartbeats = None
        self.api_key = APIKEY.read() or ''
        self.ignore = None
        self.include = None
        self.hidefilenames = None
        self.proxy = None

        self.heartbeat = heartbeat
        self.has_extra_heartbeats = False

    def add_extra_heartbeats(self, extra_heartbeats):
        self.has_extra_heartbeats = True
        self.extra_heartbeats = extra_heartbeats

    def run(self):
        """Running in background thread."""

        self.send_heartbeats()

    def send_heartbeats(self):
        heartbeat = build_heartbeat(**self.heartbeat)
        ua = 'ida-pro/%s ida-pro-wakatime/%s' % (ida_ver, VERSION)
        cmd = [
            get_cli_location(),
            '--entity', heartbeat['entity'],
            '--time', str('%f' % heartbeat['timestamp']),
            '--plugin', ua,
            '--local-file', heartbeat['idb_path'],
            '--alternate-language', 'IDA',
            '--category', 'code reviewing'  # @note: @es3n1n: lmao
        ]
        if self.api_key:
            cmd.extend(
                ['--key', str(bytes.decode(self.api_key.encode('utf8')))])
        if heartbeat['is_write']:
            cmd.append('--write')
        if heartbeat.get('alternate_project'):
            cmd.extend(['--alternate-project', heartbeat['alternate_project']])
        if heartbeat.get('lineno') is not None:
            cmd.extend(['--lineno', '{0}'.format(heartbeat['lineno'])])
        if heartbeat.get('cursorpos') is not None:
            cmd.extend(['--cursorpos', '{0}'.format(heartbeat['cursorpos'])])
        if heartbeat.get('lines_in_file') is not None:
            cmd.extend(
                ['--lines-in-file', '{0}'.format(heartbeat['lines_in_file'])])
        if self.hidefilenames:
            cmd.append('--hidefilenames')
        if self.proxy:
            cmd.extend(['--proxy', self.proxy])
        stdin = None
        inp = None
        if self.has_extra_heartbeats:
            cmd.append('--extra-heartbeats')
            stdin = PIPE
            extra_heartbeats = json.dumps(
                [build_heartbeat(**x) for x in self.extra_heartbeats])
            inp = "{0}\n".format(extra_heartbeats).encode('utf-8')

        try:
            process = Popen(cmd, stdin=stdin, stdout=PIPE, stderr=STDOUT)
            output, _err = process.communicate(input=inp)
            retcode = process.poll()
            if retcode and retcode not in [102, 112]:
                log(ERROR, 'Error #{0}'.format(retcode))
            if output:
                log(ERROR, 'wakatime-core output: {0}'.format(output))
        except:  # noqa
            log(ERROR, sys.exc_info()[1])


def handle_activity(callback_name, entity=None, is_write=False):
    project = os.path.basename(idc.get_idb_path())
    if not entity:
        entity = project

    timestamp = time.time()
    if entity != LAST_HEARTBEAT['file'] or enough_time_passed(timestamp,
                                                              is_write):
        append_heartbeat(entity, timestamp, is_write, project)
        log(DEBUG, 'heartbeat[{}, {}, {}, {}, {}]'.format(callback_name,
                                                          entity,
                                                          int(timestamp),
                                                          is_write, project))

    return 0


def append_heartbeat(entity, timestamp, is_write, project):
    global LAST_HEARTBEAT

    # add this heartbeat to queue
    heartbeat = {
        'entity': entity,
        'timestamp': timestamp,
        'is_write': is_write,
        'project': project,
        'idb_path': idc.get_idb_path()
    }
    HEARTBEATS.put_nowait(heartbeat)

    # make this heartbeat the LAST_HEARTBEAT
    LAST_HEARTBEAT = {
        'file': entity,
        'time': timestamp,
        'is_write': is_write,
    }

    # process the queue of heartbeats in the future
    process_queue(timestamp)


def process_queue(timestamp):
    global LAST_HEARTBEAT_SENT_AT

    if not is_cli_installed():
        return

    # Prevent sending heartbeats more often than SEND_BUFFER_SECONDS
    now = int(time.time())
    if timestamp != LAST_HEARTBEAT['time'] \
            and LAST_HEARTBEAT_SENT_AT > now - SEND_BUFFER_SECONDS:
        return
    LAST_HEARTBEAT_SENT_AT = now

    try:
        heartbeat = HEARTBEATS.get_nowait()
    except queue.Empty:
        return

    has_extra_heartbeats = False
    extra_heartbeats = []
    try:
        while True:
            extra_heartbeats.append(HEARTBEATS.get_nowait())
            has_extra_heartbeats = True
    except queue.Empty:
        pass

    thread = SendHeartbeatsThread(heartbeat)
    if has_extra_heartbeats:
        thread.add_extra_heartbeats(extra_heartbeats)
    thread.start()


class IDACallbacks(idaapi.Hexrays_Hooks):
    # @note: @es3n1n: New pseudocode view has been opened.
    def open_pseudocode(self, vu):
        return handle_activity('open_pseudocode',
                               idc.get_func_name(vu.cfunc.body.ea), False)

    # @note: @es3n1n: Existing pseudocode text has been refreshed
    def refresh_pseudocode(self, vu):
        return handle_activity('refresh_pseudocode',
                               idc.get_func_name(vu.cfunc.body.ea), False)

    # @note: @es3n1n: Keyboard has been hit.
    def keyboard(self, vu, *args):
        return handle_activity('keyboard',
                               idc.get_func_name(vu.cfunc.body.ea), True)

    # @note: @es3n1n: Mouse right click
    def right_click(self, vu):
        return handle_activity('right_click',
                               idc.get_func_name(vu.cfunc.body.ea), False)

    # @note: @es3n1n: Mouse double click.
    def double_click(self, vu, *args):
        return handle_activity('double_click',
                               idc.get_func_name(vu.cfunc.body.ea), False)

    # @note: @es3n1n: Current cursor position has been changed.
    def curpos(self, vu):
        return handle_activity('curpos',
                               idc.get_func_name(vu.cfunc.body.ea), False)

    # @note: @es3n1n: Local variable got renamed.
    def lvar_name_changed(self, vu, *args):
        return handle_activity('lvar_name_changed',
                               idc.get_func_name(vu.cfunc.body.ea), True)

    # @note: @es3n1n: Local variable type got changed.
    def lvar_type_changed(self, vu, *args):
        return handle_activity('lvar_type_changed',
                               idc.get_func_name(vu.cfunc.body.ea), True)

    # @note: @es3n1n: Local variable comment got changed.
    def lvar_cmt_changed(self, vu, *args):
        return handle_activity('lvar_cmt_changed',
                               idc.get_func_name(vu.cfunc.body.ea), True)

    # @note: @es3n1n: Local variable mapping got changed.
    def lvar_mapping_changed(self, vu, *args):
        return handle_activity('lvar_mapping_changed',
                               idc.get_func_name(vu.cfunc.body.ea), True)

    # @note: @es3n1n: Comment got changed.
    def cmt_changed(self, cfunc, *args):
        return handle_activity('cmt_changed',
                               idc.get_func_name(cfunc.body.ea), True)


def prompt_api_key():
    if APIKEY.read():
        return True

    default_value = 'https://wakatime.com/settings/account'
    if APIKEY.read():
        default_value = APIKEY.read()

    new_key = ask_str(default_value, 1488, 'Enter your wakatime API key: ')
    if not new_key:
        return

    log(INFO, 'Set api key!')
    APIKEY.write(new_key)


class WakaTimePlugin(idaapi.plugin_t):
    comment = "WakaTime integration for IDA Pro by @es3n1n"
    help = ""
    wanted_name = "WakaTime"
    wanted_hotkey = ""
    flags = idaapi.PLUGIN_KEEP
    callbacks = IDACallbacks()

    def init(self):
        log(INFO, 'Loaded')
        log(INFO, 'v{} by @es3n1n, 2022'.format(VERSION))

        if not is_cli_latest():
            th = DownloadCLI()
            th.start()

        prompt_api_key()
        self.callbacks.hook()

        return idaapi.PLUGIN_KEEP

    def term(self):
        pass

    @staticmethod
    def run(*args):  # noqa
        dbg = NETNODE.get('debug', "false")
        fmt = '''AUTOHIDE NONE
WakaTime integration for IDA Pro
Plugin version: v{}
Plugin author: @es3n1n
Wakatime version: {}
Debug mode: {}'''.format(VERSION, WAKATIME_CLI_VERSION, dbg)
        ret = ask_buttons('~D~ebug', '~G~it repo', '~C~ancel', -1, fmt)

        if ret == 1:
            dbg = "false" if dbg == "true" else "true"
            NETNODE['debug'] = dbg
            log(INFO, 'Set debug to: {}'.format(dbg))

        if ret == 0:
            log(INFO, 'Opening git repo')
            webbrowser.open_new('https://github.com/es3n1n/ida-wakatime-py')


def PLUGIN_ENTRY():  # noqa
    return WakaTimePlugin()
