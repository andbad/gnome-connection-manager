# -*- coding: utf-8 -*-
# Backend de acceso a archivos para el panel: SFTP (paramiko) o filesystem local.
# La interfaz es comun para ambos (list/stat/get/put/...).

import os
import stat
import shutil

try:
    import paramiko
except ImportError:
    paramiko = None


class SftpError(Exception):
    pass


class HostKeyPrompt(Exception):
    '''host desconocido: el llamador debe pedir confirmacion al usuario'''
    def __init__(self, hostname, key):
        Exception.__init__(self, hostname)
        self.hostname = hostname
        self.key = key

    def fingerprint(self):
        return ':'.join('%02x' % b for b in bytearray(self.key.get_fingerprint()))


def _entry_sort_key(e):
    return (not e['dir'], e['name'].lower())


class ChannelBase:
    '''interfaz comun; los metodos devuelven dicts {'name','dir','size','mtime','path'}'''

    def listdir(self, path):
        raise NotImplementedError

    def stat(self, path):
        raise NotImplementedError

    def get(self, remote_path, local_path):
        raise NotImplementedError

    def put(self, local_path, remote_path):
        raise NotImplementedError

    def error(self):
        return None

    def close(self):
        pass


class LocalChannel(ChannelBase):
    def listdir(self, path):
        entries = []
        try:
            for name in os.listdir(path):
                try:
                    st = os.lstat(os.path.join(path, name))
                except OSError:
                    continue
                entries.append({
                    'name': name,
                    'dir': stat.S_ISDIR(st.st_mode),
                    'link': stat.S_ISLNK(st.st_mode),
                    'size': st.st_size,
                    'mtime': st.st_mtime,
                    'path': os.path.join(path, name),
                })
        except OSError as e:
            raise SftpError(str(e))
        entries.sort(key=_entry_sort_key)
        return entries

    def stat(self, path):
        try:
            st = os.stat(path)
        except OSError:
            return None
        return {'name': os.path.basename(path.rstrip('/')) or path,
                'dir': stat.S_ISDIR(st.st_mode), 'link': False,
                'size': st.st_size, 'mtime': st.st_mtime, 'path': path}

    def get(self, remote_path, local_path):
        shutil.copy(remote_path, local_path)

    def put(self, local_path, remote_path):
        shutil.copy(local_path, remote_path)


class _MissingPolicy:
    def missing_host_key(self, client, hostname, key):
        raise HostKeyPrompt(hostname, key)


class SftpChannel(ChannelBase):
    '''envuelve SSHClient+SFTP de paramiko con la interfaz comun'''

    def __init__(self, client, sftp, known_hosts_path):
        self.client = client
        self.sftp = sftp
        self.known_hosts_path = known_hosts_path
        self._error = None

    def error(self):
        return self._error

    def accept_host_key(self):
        # se llama tras confirmar el prompt: guardar la key y reconectar lo hace el llamador
        pass

    def listdir(self, path):
        try:
            attrs = self.sftp.listdir_attr(path)
        except IOError as e:
            raise SftpError(str(e))
        entries = []
        for a in attrs:
            if a.filename in ('.', '..'):
                continue
            is_dir = stat.S_ISDIR(a.st_mode or 0)
            entries.append({
                'name': a.filename,
                'dir': is_dir,
                'link': stat.S_ISLNK(a.st_mode or 0),
                'size': a.st_size or 0,
                'mtime': a.st_mtime or 0,
                'path': path.rstrip('/') + '/' + a.filename if path != '/' else '/' + a.filename,
            })
        entries.sort(key=_entry_sort_key)
        return entries

    def stat(self, path):
        try:
            a = self.sftp.stat(path)
        except IOError:
            return None
        return {'name': os.path.basename(path.rstrip('/')) or path,
                'dir': stat.S_ISDIR(a.st_mode or 0), 'link': False,
                'size': a.st_size or 0, 'mtime': a.st_mtime or 0, 'path': path}

    def get(self, remote_path, local_path):
        try:
            self.sftp.get(remote_path, local_path)
        except IOError as e:
            raise SftpError(str(e))

    def put(self, local_path, remote_path):
        try:
            self.sftp.put(local_path, remote_path)
        except IOError as e:
            raise SftpError(str(e))

    def close(self):
        try:
            self.sftp.close()
            self.client.close()
        except Exception:
            pass


def connect_ssh(host, user, port, password, private_key, known_hosts_path, accept_key_for=None):
    '''crea el canal SFTP. Lanza HostKeyPrompt si el host es desconocido;
    si accept_key_for == host, la key desconocida se acepta y se guarda'''
    if paramiko is None:
        raise SftpError("python3-paramiko no esta instalado (sudo apt install python3-paramiko)")

    client = paramiko.SSHClient()
    if accept_key_for == host:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    else:
        client.set_missing_host_key_policy(_MissingPolicy())
    client.load_system_host_keys()
    # confianza previa de OpenSSH del usuario (~/.ssh/known_hosts): sin prompt
    user_kh = os.path.join(os.path.expanduser('~'), '.ssh', 'known_hosts')
    if os.path.exists(user_kh):
        try:
            client.load_host_keys(user_kh)
        except Exception:
            pass
    if os.path.exists(known_hosts_path):
        client.load_host_keys(known_hosts_path)

    kw = dict(hostname=host, port=int(port or 22), username=user or None,
              timeout=15, banner_timeout=15, auth_timeout=15)
    if password:
        kw['password'] = password
    if private_key:
        kw['key_filename'] = private_key
    # sin password/key explicitos: intenta agente ssh y claves por defecto
    kw['allow_agent'] = True
    kw['look_for_keys'] = not bool(password)

    client.connect(**kw)
    if accept_key_for == host:
        # el usuario Confio en la key desconocida (AutoAddPolicy la agrego a los
        # host keys del cliente): persistirla en nuestro known_hosts
        try:
            client.save_host_keys(known_hosts_path)
        except Exception:
            pass
    sftp = client.open_sftp()
    return SftpChannel(client, sftp, known_hosts_path)


def save_host_key(client_obj, hostname, key, known_hosts_path):
    '''guarda la key aceptada por el usuario y persiste known_hosts'''
    try:
        hk = client_obj.get_host_keys()
        hk.add(hostname, key.get_name(), key)
        client_obj.save_host_keys(known_hosts_path)
    except Exception:
        pass
