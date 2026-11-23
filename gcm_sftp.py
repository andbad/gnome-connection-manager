# -*- coding: utf-8 -*-
# Backend de acceso a archivos para el panel: SFTP (paramiko) o filesystem local.
# La interfaz es comun para ambos (list/stat/get/put/...).

import os
import stat
import shutil
import socket
import unicodedata

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


def usable_password(pw):
    '''True se la password salvata e' utilizzabile: decifrata bene e senza
    caratteri di controllo (le password decifrate con la chiave sbagliata
    escono come spazzatura binaria: meglio non usarle e chiederle all'utente)'''
    if not pw:
        return False
    return all(not unicodedata.category(c).startswith('C') for c in pw)


def describe_auth_error(auth_exc, key_errors, second_exc=None):
    '''messaggio leggibile: distingue chiave mancante/invalida, password
    assente e credenziali rifiutate'''
    parts = []
    base = ''
    if key_errors:
        parts.append('; '.join(key_errors))
    if auth_exc is not None:
        base = str(auth_exc).strip().rstrip('.')
        if base:
            parts.append(base)
    if second_exc is not None:
        b2 = str(second_exc).strip().rstrip('.')
        if b2 and b2 != base:
            parts.append(b2)
    if not parts:
        parts.append("autenticacion rechazada")
    return '. '.join(parts) + '.'


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
                "%s es una clave publica" % os.path.basename(path))
        if not os.path.exists(path):
            raise paramiko.SSHException("archivo de clave no encontrado: %s" % path)
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

    def __call__(self, title, instructions, prompt_list):
        # istruzioni del server (es. "Invalid username or password"): le
        # antepongo al primo prompt cosi' il popup le mostra
        prefix = ''
        if instructions and instructions.strip():
            prefix = instructions.strip() + '\n'
        first = True
        responses = []
        for prompt, echo in prompt_list:
            if first and prefix:
                prompt = prefix + prompt
            first = False
            low = prompt.lower()
            is_pw = ('password' in low or 'contrase' in low or 'passcode' in low)
            if is_pw and not self.password_prompt_used and self.saved_password:
                self.password_prompt_used = True
                responses.append(self.saved_password)
                continue
            if self.canceled:
                responses.append('')
                continue
            answer = self.handler(prompt)
            if answer is None:
                self.canceled = True
                responses.append('')
                continue
            responses.append(answer)
        return responses


def _hk_name(host, port):
    p = int(port or 22)
    return host if p == 22 else "[%s]:%s" % (host, p)


def _verify_host_key(client, hk_name, server_key):
    '''come fa SSHClient ma trattando gli algoritmi separatamente: un host
    gia noto che oggi presenta un ALGORITMO nuovo (es. prima ecdsa, oggi
    ed25519) non e' un attacco, e' un cambiamento normale del server: si
    chiede conferma all'utente (HostKeyPrompt). Se invece l'algoritmo coincide
    e la chiave e' diversa -> BadHostKeyException (chiave cambiata davvero)'''
    keys = client.get_host_keys().lookup(hk_name)
    if not keys:
        raise HostKeyPrompt(hk_name, server_key)
    same_algo = keys.get(server_key.get_name())
    if same_algo is None:
        raise HostKeyPrompt(hk_name, server_key)
    if same_algo != server_key:
        raise paramiko.BadHostKeyException(hk_name, server_key, same_algo)


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
        # OTP: il default di paramiko (30 s) aborta l'autenticazione mentre
        # l'utente cerca il token; il limite reale lo da' il popup (2 minuti)
        t.auth_timeout = None
        client._transport = t
        # come fa SSHClient.connect: se l'host e' gia' noto, da' priorita
        # all'algoritmo noto (evita che il server presenti ed25519 quando
        # known_hosts ha ecdsa: sembrerebbe chiave cambiata)
        hk_name = _hk_name(host, port)
        keys = client.get_host_keys().lookup(hk_name)
        if keys:
            sec_opts = t.get_security_options()
            first = list(keys.keys())[0]
            sec_opts.key_types = [first] + [x for x in sec_opts.key_types if x != first]
        t.start_client(timeout=15)
        server_key = t.get_remote_server_key()
        if not keys:
            # missing policy: HostKeyPrompt se non accettata; AutoAdd l'aggiunge
            client._policy.missing_host_key(client, hk_name, server_key)
            client.save_host_keys(known_hosts_path) if known_hosts_path else None
        else:
            _verify_host_key(client, hk_name, server_key)
        try:
            t.auth_interactive(user or None, ai)
        except paramiko.BadAuthenticationType as ba:
            if 'password' not in ba.allowed_types:
                raise
            # server che offre solo auth password: chiedi la password (un solo
            # prompt) e usa auth_password
            if ai.canceled or ai.handler is None:
                raise
            pw = ai.handler("Password: ")
            if pw is None:
                ai.canceled = True
                raise
            t.auth_password(user or None, pw)
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
    if password and not usable_password(password):
        # decifrata male (chiave di cifratura cambiata): non usarla in modo
        # automatico, sara' chiesta all'utente via popup quando necessario
        key_errors.append("password salvata non decifrabile")
        password = None
    if private_key and private_key.strip():
        try:
            pkey = load_one_key(private_key.strip(), password or None)
        except Exception as e:
            key_errors.append(str(e))
            pkey = None

    client = _make_client(known_hosts_path, accept_key_for, host)

    kw = dict(hostname=host, port=int(port or 22), username=user or None,
              timeout=15, banner_timeout=15,
              auth_timeout=240,  # OTP: non interrompere mentre l'utente cerca il token
              allow_agent=True, look_for_keys=not bool(password))
    if password:
        kw['password'] = password
    if pkey is not None:
        kw['pkey'] = pkey

    auth_exc = None
    try:
        client.connect(**kw)
    except paramiko.BadHostKeyException as bh:
        # host noto ma con un algoritmo di host key nuovo: non e' un attacco,
        # si chiede conferma come per un host mai visto
        _verify_host_key(client, _hk_name(host, port), bh.server_key)
        raise
    except (paramiko.AuthenticationException, paramiko.BadAuthenticationType,
            paramiko.PasswordRequiredException) as e:
        auth_exc = e
    if auth_exc is not None and interactive is None:
        # nessun popup disponibile: il chiamante (GUI) puo' ritentare passando
        # interactive=handler; niente tentativo cieco (evita login falliti nei
        # log del server quando mancano le credenziali)
        raise AuthenticationPromptRequired(describe_auth_error(auth_exc, key_errors))
    if auth_exc is not None:
        # reintento con keyboard-interactive (OTP o password interactiva) su un
        # transport nuovo. Nota: dentro l'handler non si lanciano eccezioni (
        # gira sul thread del transport e ucciderebbe la connessione):
        # AuthInteractive registra i flags e lascia fallire in modo pulito.
        ai = AuthInteractive(password, interactive)
        try:
            client = _interactive_auth(host, port, user, ai, known_hosts_path,
                                       accept_key_for)
        except HostKeyPrompt:
            raise
        except Exception as e2:
            if ai.canceled:
                raise SftpError("autenticacion cancelada por el usuario")
            raise AuthenticationPromptRequired(describe_auth_error(auth_exc, key_errors, e2), ai)
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
