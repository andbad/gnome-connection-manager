# -*- coding: utf-8 -*-
# Backend de acceso a archivos para el panel: SFTP (paramiko) o filesystem local.
# La interfaz es comun para ambos (list/stat/get/put/...).

import os
import stat
import shutil
import socket

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


class AuthenticationPromptRequired(Exception):
    '''autenticacion normal fallida: el llamador puede reintentar passando
    interactive=handler(prompt)->str para OTP/keyboard-interactive'''
    def __init__(self, message, prompter=None):
        Exception.__init__(self, message)
        self.prompter = prompter


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


def load_one_key(path, passphrase=None):
    '''carica una chiave privata provando tutti gli algoritmi; solleva
    SSHException se nessuna coincide. Se l'utente indico per errore il file
    .pub, si prova l'omologo privato (rimuovendo l'estensione)'''
    tried_pub = False
    while True:
        if path.endswith('.pub'):
            alt = path[:-4]
            if not tried_pub and os.path.exists(alt):
                path = alt
                tried_pub = True
                continue
            raise paramiko.SSHException(
                "%s e' una chiave pubblica" % os.path.basename(path))
        if not os.path.exists(path):
            raise paramiko.SSHException("file chiave non trovato: %s" % path)
        last_err = None
        for cls in (paramiko.RSAKey, paramiko.ECDSAKey, paramiko.Ed25519Key,
                    paramiko.DSSKey):
            try:
                return cls.from_private_key_file(path, password=passphrase)
            except paramiko.PasswordRequiredException:
                if passphrase:
                    raise
                last_err = paramiko.PasswordRequiredException(
                    "la chiave %s richiede una passphrase" % os.path.basename(path))
            except Exception as e:
                last_err = e
        raise paramiko.SSHException(str(last_err))


class AuthInteractive:
    '''adapter di auth_interactive: precompila le richieste di password con
    quella salvata e delega all'handler (popup) le altre (es. OTP)''

    handler(prompt_text) -> str|None  (None = annulla l'autenticazione)

    Non lancia mai eccezioni dentro l'handler ( gira sul thread del transport:
    un'eccezione lì uccide la connessione): registra i flags e risponde vuoto
    lasciando fallire l'autenticazione in modo pulito.'''

    def __init__(self, saved_password, handler):
        self.saved_password = saved_password or ''
        self.handler = handler
        self.password_prompt_used = False
        self.canceled = False
        self.prompt_needed = False

    def __call__(self, title, instructions, prompt_list):
        responses = []
        for prompt, echo in prompt_list:
            low = prompt.lower()
            is_pw = ('password' in low or 'contrase' in low or 'passcode' in low)
            if is_pw and not self.password_prompt_used and self.saved_password:
                self.password_prompt_used = True
                responses.append(self.saved_password)
                continue
            if self.canceled or self.prompt_needed:
                responses.append('')
                continue
            if self.handler is None:
                # nessun popup disponibile: il chiamante puo' ritentare con
                # interactive=handler (secondo tentativo con GUI)
                self.prompt_needed = True
                responses.append('')
                continue
            answer = self.handler(prompt)
            if answer is None:
                self.canceled = True
                responses.append('')
                continue
            responses.append(answer)
        return responses


def _make_client(known_hosts_path, accept_key_for=None, host=None):
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
    if known_hosts_path and os.path.exists(known_hosts_path):
        client.load_host_keys(known_hosts_path)
    return client


def _interactive_auth(host, port, user, ai, known_hosts_path, accept_key_for=None):
    '''keyboard-interactive su un transport nuovo (paramiko chiude il
    transport quando un tentativo di autenticazione fallisce)'''''
    client = _make_client(known_hosts_path, accept_key_for, host)
    sock = socket.create_connection((host, int(port or 22)), timeout=15)
    t = None
    try:
        t = paramiko.Transport(sock)
        client._transport = t
        t.start_client(timeout=15)
        # verifica host key come fa SSHClient.connect
        p = int(port or 22)
        hk_name = host if p == 22 else "[%s]:%s" % (host, p)
        keys = client.get_host_keys().lookup(hk_name)
        server_key = t.get_remote_server_key()
        if not keys:
            # missing policy: HostKeyPrompt se non accettata; AutoAdd l'aggiunge
            client._policy.missing_host_key(client, hk_name, server_key)
            client.save_host_keys(known_hosts_path) if known_hosts_path else None
        elif server_key not in list(keys.values()):
            raise paramiko.BadHostKeyException(host, server_key, list(keys.values())[0])
        t.auth_interactive(user or None, ai)
        return client
    except Exception:
        try:
            if t:
                t.close()
        except Exception:
            pass
        raise


def connect_ssh(host, user, port, password, private_key, known_hosts_path,
                accept_key_for=None, interactive=None):
    '''crea il canale SFTP. Lanza HostKeyPrompt si el host es desconocido;
    si accept_key_for == host, la key desconocida se acepta y se guarda.
    interactive: callable(prompt)->str|None per OTP/keyboard-interactive.
    La chiave privata indicada se salta con aviso si no se puede cargar
    (sigue con agente/otras claves), igual que hace ssh en la terminal.'''
    if paramiko is None:
        raise SftpError("python3-paramiko no esta instalado (sudo apt install python3-paramiko)")

    key_errors = []
    pkey = None
    if private_key and private_key.strip():
        try:
            pkey = load_one_key(private_key.strip(), password or None)
        except Exception as e:
            key_errors.append(str(e))
            pkey = None

    client = _make_client(known_hosts_path, accept_key_for, host)

    kw = dict(hostname=host, port=int(port or 22), username=user or None,
              timeout=15, banner_timeout=15, auth_timeout=15,
              allow_agent=True, look_for_keys=not bool(password))
    if password:
        kw['password'] = password
    if pkey is not None:
        kw['pkey'] = pkey

    auth_exc = None
    try:
        client.connect(**kw)
    except (paramiko.AuthenticationException, paramiko.BadAuthenticationType,
            paramiko.PasswordRequiredException) as e:
        auth_exc = e
    if auth_exc is not None:
        # reintento con keyboard-interactive (OTP o password interactiva).
        # Si falli anche li, si propaga AuthenticationPromptRequired affinche
        # il chiamante possa ripetere con un handler (popup OTP) funzionante.
        # Nota: non si lanciano eccezioni dentro l'handler interactive (verrebbe
        # ucciso il thread del transport): AuthInteractive registra i flags e
        # risponde vuoto, lasciando fallire l'autenticazione in modo pulito.
        ai = AuthInteractive(password, interactive)
        try:
            client = _interactive_auth(host, port, user, ai, known_hosts_path,
                                       accept_key_for)
        except HostKeyPrompt:
            raise
        except Exception as e2:
            if ai.canceled:
                raise SftpError("autenticacion cancelada por el usuario")
            msg = str(auth_exc) if str(auth_exc) else str(e2)
            if key_errors:
                msg += " (chiave privata: %s)" % '; '.join(key_errors)
            raise AuthenticationPromptRequired(msg, ai)
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
