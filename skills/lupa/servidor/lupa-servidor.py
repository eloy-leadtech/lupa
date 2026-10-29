#!/usr/bin/env python3
"""Lupa · un servidor por dentro.

Solo LEE: no instala nada, no cambia nada y no abre el contenido de ningún secreto (de un fichero
de claves mira solo si es legible por cualquiera y si la cabecera dice PRIVATE KEY). Saca una foto
en JSON de lo que importa para la seguridad: parches, qué escucha y desde dónde, con quién habla,
SSH, usuarios con poder, contenedores, agentes de seguridad y ficheros delicados mal protegidos.

Uso, en cada servidor del proyecto (como root, para ver procesos y la config de SSH):
    sudo python3 -I lupa-servidor.py > nombre-del-servidor.json
o desde tu equipo:
    ssh servidor 'sudo python3 -I -' < lupa-servidor.py > nombre-del-servidor.json
(-I: Python no carga módulos de la carpeta desde la que se lanza.)

Python 3.6 o más reciente, sin librerías externas. Tarda unos segundos.
"""
import glob
import grp
import ipaddress
import json
import os
import platform
import pwd
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time

VERSION = 1
MUESTRAS = 3          # fotos de las conexiones, separadas unos segundos, para pillar las cortas
TOPE_PARES = 40       # pares privados que se guardan por puerto de entrada
TOPE_SALIDAS = 300


def sh(cmd, timeout=60):
    """Ejecuta sin shell y devuelve (código, salida). Nunca lanza."""
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout)
        return p.returncode, p.stdout.decode('utf-8', 'replace')
    except Exception:
        return -1, ''


def leer(path, n=200000):
    try:
        with open(path, 'r', errors='replace') as f:
            return f.read(n)
    except Exception:
        return ''


def es_publica(ip):
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified
                    or a in ipaddress.ip_network('100.64.0.0/10'))
    except ValueError:
        return False


# ---------------------------------------------------------------- equipo
def equipo():
    osr = {}
    for line in leer('/etc/os-release').splitlines():
        if '=' in line:
            k, v = line.split('=', 1)
            osr[k] = v.strip().strip('"')
    _, ips = sh(['hostname', '-I'])
    up = leer('/proc/uptime').split()
    return {
        'nombre': socket.gethostname(), 'so': osr.get('PRETTY_NAME', platform.platform()),
        'so_id': osr.get('ID', ''), 'so_version': osr.get('VERSION_ID', ''), 'kernel': platform.release(),
        'arquitectura': platform.machine(), 'ips': ips.split(), 'arrancado_hace_dias': round(float(up[0]) / 86400, 1) if up else None,
        'root': os.geteuid() == 0, 'python': platform.python_version(),
    }


# ---------------------------------------------------------------- parches
def parches(so_id):
    out = {'gestor': None, 'pendientes': None, 'seguridad': None, 'reinicio_pendiente': os.path.exists('/var/run/reboot-required'),
           'automaticas': None, 'listas_hace_dias': None}
    if shutil.which('apt'):
        out['gestor'] = 'apt'
        # solo lee las listas que ya hay: no actualiza nada. Si son viejas, el número engaña y se dice.
        rels = glob.glob('/var/lib/apt/lists/*Release')
        if rels:
            out['listas_hace_dias'] = round((time.time() - max(os.path.getmtime(r) for r in rels)) / 86400, 1)
        _, txt = sh(['apt', 'list', '--upgradable'], 120)
        lines = [l for l in txt.splitlines() if '/' in l and 'upgradable' in l]
        out['pendientes'] = len(lines)
        out['seguridad'] = len([l for l in lines if '-security' in l])
        out['ejemplos_seguridad'] = [l.split('/')[0] for l in lines if '-security' in l][:15]
        _, cfg = sh(['apt-config', 'dump'])
        m = re.search(r'APT::Periodic::Unattended-Upgrade "(\d+)"', cfg)
        out['automaticas'] = bool(m and m.group(1) != '0') and os.path.exists('/usr/bin/unattended-upgrade')
    elif shutil.which('dnf') or shutil.which('yum'):
        mgr = 'dnf' if shutil.which('dnf') else 'yum'
        out['gestor'] = mgr
        # -C: solo la caché local, sin salir a internet; el log de dnf va a una carpeta temporal, no a /var/log
        logdir = tempfile.mkdtemp(prefix='lupa-dnf-')
        try:
            base = [mgr, '-C', '-q', '--setopt=logdir=' + logdir]
            code, sec = sh(base + ['updateinfo', 'list', '--security'], 120)
            sec_l = [l for l in sec.splitlines() if l.strip() and not l.startswith(('Last metadata', 'Updates Information'))]
            # sin caché (dnf clean all, o nunca refrescada) dnf falla: entonces no se sabe, no es «0 parches»
            out['seguridad'] = len(sec_l) if code == 0 else None
            out['ejemplos_seguridad'] = sorted({l.split()[-1] for l in sec_l if l.split()})[:15]
            code, upd = sh(base + ['check-update'], 120)
            out['pendientes'] = len([l for l in upd.splitlines() if re.match(r'^\S+\.\S+\s+\S+\s+\S+', l)]) if code in (0, 100) else None
        finally:
            shutil.rmtree(logdir, ignore_errors=True)
        # Amazon Linux 2023 fija el repositorio en la versión con la que se instaló: los parches llegan en
        # versiones nuevas y no se ven ni se instalan solos salvo que releasever sea «latest»
        if so_id == 'amzn':
            out['releasever'] = (leer('/etc/dnf/vars/releasever').strip() or None)
        caches = glob.glob('/var/cache/dnf/*/repodata/repomd.xml') + glob.glob('/var/cache/yum/*/*/repomd.xml')
        if caches:
            out['listas_hace_dias'] = round((time.time() - max(os.path.getmtime(c) for c in caches)) / 86400, 1)
        code, _ = sh(['systemctl', 'is-enabled', 'dnf-automatic.timer'])
        code2, _ = sh(['systemctl', 'is-enabled', 'dnf-automatic-install.timer'])
        out['automaticas'] = code == 0 or code2 == 0
        if shutil.which('needs-restarting'):
            code, _ = sh(['needs-restarting', '-r'])
            out['reinicio_pendiente'] = code == 1
    return out


# ---------------------------------------------------------------- red
SS_PROC = re.compile(r'users:\(\("([^"]+)"')


def partir(addr):
    """'10.0.0.1:22' / '[::ffff:10.0.0.1]:22' / '[fe80::1]%ens5:546' / '*:22' → (ip, puerto)."""
    ip, _, port = addr.rpartition(':')
    # primero la zona («%ens5»), que va fuera de los corchetes; luego los corchetes
    if '%' in ip:
        ip = ip.split('%')[0]
    ip = ip.strip('[]')
    if ip.startswith('::ffff:'):
        ip = ip[7:]
    return ip, int(port) if port.isdigit() else 0


def ss(args, netns_pid=None):
    """Las líneas de ss sin cabecera. Los ss antiguos (CentOS 7, Debian 9) no tienen -H: se quita a mano.
    Con netns_pid, dentro de la red de ese proceso (un contenedor). None si ss no funciona."""
    pre = ['nsenter', '-t', str(netns_pid), '-n'] if netns_pid else []
    code, txt = sh(pre + ['ss', '-H'] + args)
    if code == 0:
        return txt.splitlines()
    code, txt = sh(pre + ['ss'] + args)
    return txt.splitlines()[1:] if code == 0 else None


def escucha(netns_pid=None):
    lines = ss(['-tulnp'], netns_pid)
    if lines is None:
        return None
    out = []
    for line in lines:
        f = line.split()
        if len(f) < 5:
            continue
        ip, port = partir(f[4])
        m = SS_PROC.search(line)
        out.append({'proto': f[0], 'ip': ip, 'puerto': port, 'proceso': m.group(1) if m else ''})
    # el mismo socket en IPv4 e IPv6 cuenta una vez
    uniq = {}
    for e in out:
        uniq.setdefault((e['proto'], e['ip'], e['puerto']), e)
    return sorted(uniq.values(), key=lambda e: (e['proto'], e['puerto']))


def conexiones(escuchando, contenedores_red=()):
    """Agrupa las conexiones establecidas en entradas (alguien llama a un puerto nuestro) y salidas.
    Mira también dentro de la red de cada contenedor: lo que hacen no se ve desde la del servidor."""
    redes = [(None, {e['puerto'] for e in (escuchando or []) if e['proto'] == 'tcp'}, '')]
    for nombre, pid in contenedores_red:
        dentro = escucha(pid)
        if dentro is not None:
            redes.append((pid, {e['puerto'] for e in dentro if e['proto'] == 'tcp'}, nombre))
    entradas, salidas = {}, {}
    for i in range(MUESTRAS):
        if i:
            time.sleep(4)
        for pid, puertos, contenedor in redes:
            for line in ss(['-tnp', 'state', 'established'], pid) or []:
                f = line.split()
                if len(f) < 4:
                    continue
                lip, lport = partir(f[2])
                pip, pport = partir(f[3])
                if lip in ('127.0.0.1', '::1') or pip in ('127.0.0.1', '::1'):
                    continue
                m = SS_PROC.search(line)
                proc = m.group(1) if m else ''
                if contenedor:
                    proc = '%s (%s)' % (proc, contenedor) if proc else contenedor
                if lport in puertos:
                    e = entradas.setdefault((lport, proc), {'puerto': lport, 'proceso': proc, 'privados': {}, 'publicos': set()})
                    if es_publica(pip):
                        e['publicos'].add(pip)
                    else:
                        e['privados'][pip] = e['privados'].get(pip, 0) + 1
                else:
                    k = (pip, pport, proc)
                    salidas[k] = salidas.get(k, 0) + 1
    ent = []
    for e in entradas.values():
        top = sorted(e['privados'].items(), key=lambda x: -x[1])
        # de las IP públicas solo se guarda cuántas hay: suelen ser portátiles de personas
        ent.append({'puerto': e['puerto'], 'proceso': e['proceso'], 'pares_privados': [p for p, _ in top[:TOPE_PARES]],
                    'privados_total': len(top), 'publicos_total': len(e['publicos'])})
    sal = [{'ip': ip, 'puerto': port, 'proceso': proc, 'publica': es_publica(ip), 'veces': n}
           for (ip, port, proc), n in sorted(salidas.items(), key=lambda x: -x[1])[:TOPE_SALIDAS]]
    return sorted(ent, key=lambda e: e['puerto']), sal


def cortafuegos():
    out = {}
    if shutil.which('ufw'):
        _, t = sh(['ufw', 'status'])
        out['ufw'] = 'activo' if 'Status: active' in t else 'inactivo'
    if shutil.which('nft'):
        code, t = sh(['nft', 'list', 'ruleset'])
        if code == 0:
            out['nft_reglas'] = len([l for l in t.splitlines() if l.strip() and not l.strip().startswith(('table', 'chain', '}', 'type'))])
            out['nft_input_drop'] = bool(re.search(r'hook input .*policy drop', t))
    # con el iptables antiguo, preguntar carga módulos del kernel: solo se pregunta si ya están cargados
    if shutil.which('iptables') and leer('/proc/net/ip_tables_names').strip():
        code, t = sh(['iptables', '-S', 'INPUT'])
        if code == 0:
            out['iptables_input'] = 'DROP' if '-P INPUT DROP' in t else 'ACCEPT'
            out['iptables_reglas'] = len([l for l in t.splitlines() if l.startswith('-A')])
    out['ip_forward'] = leer('/proc/sys/net/ipv4/ip_forward').strip() == '1'
    return out


# ---------------------------------------------------------------- SSH y usuarios
SSH_KEYS = ('port', 'permitrootlogin', 'passwordauthentication', 'pubkeyauthentication', 'kbdinteractiveauthentication',
            'permitemptypasswords', 'x11forwarding', 'maxauthtries', 'allowusers', 'allowgroups', 'listenaddress')


def sshd_config(path='/etc/ssh/sshd_config', cfg=None, depth=0):
    """Lee la config de SSH como sshd: gana el primer valor y los Include se leen donde están. Un Match en el
    fichero principal corta todo lo que sigue; dentro de un Include solo el resto de ese fichero (como OpenSSH).
    Hace falta porque «sshd -T» falla si el servicio arranca por socket y no existe /run/sshd."""
    cfg = {} if cfg is None else cfg
    for line in leer(path).splitlines():
        f = line.strip().split(None, 1)
        if not f or f[0].startswith('#'):
            continue
        k, v = f[0].lower(), (f[1] if len(f) > 1 else '').strip()
        if k == 'match':
            return cfg, depth == 0
        if k == 'include' and depth < 5:
            for pat in v.split():
                for inc in sorted(glob.glob(pat if pat.startswith('/') else os.path.join('/etc/ssh', pat))):
                    cfg, stop = sshd_config(inc, cfg, depth + 1)
                    if stop:
                        return cfg, True
        elif k in SSH_KEYS and k not in cfg:
            cfg[k] = v
    return cfg, False


def ssh():
    if not shutil.which('sshd') and not os.path.exists('/usr/sbin/sshd'):
        return {'instalado': False}
    activo = any(sh(['systemctl', 'is-active', u])[0] == 0 for u in ('ssh', 'sshd', 'ssh.socket', 'sshd.socket')) if shutil.which('systemctl') else None
    code, t = sh([shutil.which('sshd') or '/usr/sbin/sshd', '-T'])
    cfg = {}
    if code == 0:
        for line in t.splitlines():
            k, _, v = line.partition(' ')
            if k in SSH_KEYS:
                cfg.setdefault(k, v)
        origen = 'sshd -T'
        leida = True
    else:
        # sin poder leer el fichero (0600 y sin root) no se sabe nada: no se rellena con valores por defecto
        leida = bool(leer('/etc/ssh/sshd_config'))
        cfg, _ = sshd_config()
        if leida:
            # lo que no se dice toma el valor por defecto de OpenSSH
            for k, v in (('port', '22'), ('permitrootlogin', 'prohibit-password'), ('passwordauthentication', 'yes'),
                         ('pubkeyauthentication', 'yes'), ('permitemptypasswords', 'no'), ('x11forwarding', 'no')):
                cfg.setdefault(k, v)
        origen = 'ficheros'
    return {'instalado': True, 'activo': activo, 'config': {k: v.lower() if k not in ('allowusers', 'allowgroups') else v for k, v in cfg.items()},
            'config_leida': leida, 'origen': origen}


def usuarios():
    shells_validas = {'/bin/bash', '/bin/sh', '/bin/zsh', '/usr/bin/bash', '/usr/bin/zsh', '/bin/dash', '/usr/bin/fish', '/bin/ksh'}
    con_shell, uid0, claves = [], [], []
    for p in pwd.getpwall():
        if p.pw_uid == 0:
            uid0.append(p.pw_name)
        if p.pw_shell in shells_validas:
            con_shell.append(p.pw_name)
        ak = os.path.join(p.pw_dir or '/nonexistent', '.ssh', 'authorized_keys')
        if os.path.isfile(ak):
            # solo cuántas claves y de qué tipo: nunca la clave
            tipos = [l.split()[0] for l in leer(ak).splitlines() if l.strip() and not l.startswith('#')]
            tipos = [t if t.startswith(('ssh-', 'ecdsa-', 'sk-')) else 'con-opciones' for t in tipos]
            if tipos:
                claves.append({'usuario': p.pw_name, 'claves': len(tipos), 'tipos': sorted(set(tipos))})
    admins = set()
    for g in ('sudo', 'wheel', 'admin', 'docker'):
        try:
            for m in grp.getgrnam(g).gr_mem:
                admins.add((m, g))
        except KeyError:
            pass
    nopasswd = []
    for f in ['/etc/sudoers'] + sorted(glob.glob('/etc/sudoers.d/*')):
        for line in leer(f).splitlines():
            if 'NOPASSWD' in line and not line.strip().startswith('#'):
                nopasswd.append({'quien': line.split()[0], 'fichero': f, 'todo': bool(re.search(r'NOPASSWD:\s*ALL\b', line))})
    return {'con_shell': con_shell, 'uid0': uid0, 'claves_ssh': claves,
            'privilegiados': [{'usuario': u, 'grupo': g} for u, g in sorted(admins)], 'sudo_sin_contrasena': nopasswd}


# ---------------------------------------------------------------- contenedores
SECRET_NAME = re.compile(r'(pass|secret|token|key|credential|pwd)', re.I)


def contenedores():
    if not shutil.which('docker'):
        return None
    code, ids = sh(['docker', 'ps', '-q'])
    if code != 0:
        return {'error': 'no se pudo hablar con Docker'}
    ids = ids.split()
    if not ids:
        return []
    _, t = sh(['docker', 'inspect'] + ids, 120)
    try:
        data = json.loads(t)
    except ValueError:
        return {'error': 'docker inspect no devolvió JSON'}
    out = []
    for c in data:
        hc, cfg = c.get('HostConfig') or {}, c.get('Config') or {}
        puertos = []
        for cport, binds in ((c.get('NetworkSettings') or {}).get('Ports') or {}).items():
            for b in binds or []:
                puertos.append({'contenedor': cport, 'ip': b.get('HostIp', ''), 'puerto': int(b.get('HostPort') or 0)})
        montajes = [m.get('Source', '') for m in c.get('Mounts') or []]
        env_names = [e.split('=', 1)[0] for e in cfg.get('Env') or []]
        out.append({
            'nombre': c.get('Name', '').lstrip('/'), 'imagen': cfg.get('Image', ''), 'creado': (c.get('Created') or '')[:10],
            'privilegiado': bool(hc.get('Privileged')), 'usuario': cfg.get('User') or 'root', 'red': hc.get('NetworkMode', ''),
            'pid_host': hc.get('PidMode') == 'host', 'capacidades': hc.get('CapAdd') or [], 'puertos': puertos,
            'socket_docker': any(m.endswith('docker.sock') for m in montajes),
            'monta_raiz': any(m in ('/', '/etc', '/root', '/var/run', '/proc', '/sys') for m in montajes),
            'variables_secretas': len([n for n in env_names if SECRET_NAME.search(n)]),
            # para mirar sus conexiones desde dentro de su red; no se guarda en la foto
            '_pid': int((c.get('State') or {}).get('Pid') or 0),
        })
    return out


def redes_docker():
    """Las subredes de Docker de este servidor: sus IP son contenedores propios, no vecinos de red."""
    if not shutil.which('docker'):
        return []
    code, ids = sh(['docker', 'network', 'ls', '-q'])
    if code != 0 or not ids.split():
        return []
    _, t = sh(['docker', 'network', 'inspect'] + ids.split(), 60)
    try:
        return sorted({c['Subnet'] for n in json.loads(t) for c in ((n.get('IPAM') or {}).get('Config') or []) if c.get('Subnet')})
    except (ValueError, KeyError, TypeError):
        return []


# ---------------------------------------------------------------- servicios y agentes
AGENTES = {'wazuh-agent': 'Wazuh', 'wazuh-manager': 'Wazuh (manager)', 'amazon-ssm-agent': 'AWS SSM', 'snap.amazon-ssm-agent.amazon-ssm-agent': 'AWS SSM',
           'falcon-sensor': 'CrowdStrike', 'mdatp': 'Microsoft Defender', 'osqueryd': 'osquery', 'auditd': 'auditd',
           'fail2ban': 'fail2ban', 'netbird': 'NetBird', 'amazon-cloudwatch-agent': 'CloudWatch', 'falco': 'Falco', 'crowdsec': 'CrowdSec'}


def servicios():
    if not shutil.which('systemctl'):
        return {'en_marcha': [], 'agentes': []}
    _, t = sh(['systemctl', 'list-units', '--type=service', '--state=running', '--no-legend', '--plain'])
    names = sorted({l.split()[0].replace('.service', '') for l in t.splitlines() if l.strip()})
    agentes = sorted({v for k, v in AGENTES.items() if k in names or any(n.startswith(k + '@') for n in names)})
    return {'en_marcha': names, 'agentes': agentes}


def endurecimiento():
    out = {'aslr': leer('/proc/sys/kernel/randomize_va_space').strip()}
    code, t = sh(['aa-status', '--enabled'])
    out['apparmor'] = code == 0
    code, t = sh(['getenforce'])
    out['selinux'] = t.strip() or None
    code, t = sh(['timedatectl', 'show', '-p', 'NTPSynchronized', '--value'])
    out['hora_sincronizada'] = t.strip() == 'yes' if code == 0 else None
    return out


# ---------------------------------------------------------------- ficheros delicados
NOMBRES = re.compile(r'(^\.env(\..+)?$|\.env$|\.pem$|\.key$|^id_(rsa|dsa|ecdsa|ed25519)$|\.p12$|\.pfx$|\.kdbx$|^\.pgpass$|^\.my\.cnf$|^\.netrc$|'
                     r'^credentials(\.json)?$|\.tfstate$|^\.git-credentials$|^htpasswd$|^\.htpasswd$)', re.I)
RAICES = ['/opt', '/srv', '/home', '/root', '/etc', '/var/www', '/usr/local/etc', '/var/lib/docker/volumes']
SALTAR = {'/etc/ssl/certs', '/etc/pki/ca-trust', '/usr/share', '/etc/ca-certificates', 'node_modules', '.git', 'site-packages', 'dist-packages',
          'test_data', 'testdata', 'fixtures'}
# plantillas y ficheros de herramientas que se llaman como un secreto pero no lo son: si se cuentan, tapan los de verdad
NO_SECRETO = re.compile(r'\.(example|sample|template|dist|tpl|default)$|^go\.env$', re.I)


_PASO = {}


def alcanzable(p):
    """¿Puede «otros» llegar al fichero? Hace falta permiso de paso (o+x) en todas las carpetas de encima:
    un .env 0644 dentro de /root (0700) no lo lee nadie más."""
    d = os.path.dirname(p)
    while d and d != '/':
        if d not in _PASO:
            try:
                _PASO[d] = bool(os.stat(d).st_mode & stat.S_IXOTH)
            except OSError:
                _PASO[d] = False
        if not _PASO[d]:
            return False
        d = os.path.dirname(d)
    return True


GRAVE = re.compile(r'(^\.env$|credentials|\.pgpass$|\.netrc$|\.git-credentials$|\.tfstate$|^id_)', re.I)


def ficheros():
    found, visto, t0 = [], 0, time.time()
    for raiz in RAICES:
        for d, dirs, files in os.walk(raiz):
            dirs[:] = [x for x in dirs if x not in SALTAR and os.path.join(d, x) not in SALTAR and not os.path.islink(os.path.join(d, x))]
            if d.count(os.sep) - raiz.count(os.sep) >= 6:
                dirs[:] = []
            for n in files:
                visto += 1
                if not NOMBRES.search(n) or NO_SECRETO.search(n):
                    continue
                p = os.path.join(d, n)
                try:
                    st = os.lstat(p)
                except OSError:
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue
                cab = ''
                if n.lower().endswith(('.pem', '.key')):
                    # sin seguir enlaces y sin bloquearse: alguien podría cambiar el fichero por un FIFO entre
                    # el lstat y la lectura, y root se quedaría esperando
                    try:
                        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                        try:
                            if stat.S_ISREG(os.fstat(fd).st_mode):
                                cab = os.read(fd, 64).decode('ascii', 'replace')
                        finally:
                            os.close(fd)
                    except OSError:
                        pass
                    # un certificado es público: solo cuenta si es una clave privada
                    if 'PRIVATE KEY' not in cab:
                        continue
                otros = bool(st.st_mode & stat.S_IROTH) and alcanzable(p)
                grupo = bool(st.st_mode & stat.S_IRGRP)
                try:
                    dueno = pwd.getpwuid(st.st_uid).pw_name
                except KeyError:
                    dueno = str(st.st_uid)
                found.append({'ruta': p, 'modo': oct(st.st_mode & 0o777), 'dueno': dueno, 'legible_por_todos': otros,
                              'legible_por_grupo': grupo, 'clave_privada': 'PRIVATE KEY' in cab})
            if time.time() - t0 > 40 or visto > 400000:
                return {'lista': primero_lo_grave(found), 'completo': False, 'total': len(found)}
    return {'lista': primero_lo_grave(found), 'completo': True, 'total': len(found)}


def primero_lo_grave(found, tope=300):
    """Antes de recortar, lo que cualquiera puede leer y lo que más daño hace: claves privadas, .env, credenciales."""
    found.sort(key=lambda f: (not f['legible_por_todos'], not f['clave_privada'], not GRAVE.search(os.path.basename(f['ruta']))))
    return found[:tope]


def seguro(fn, *args, defecto=None):
    """Una sección que falla no tira la foto entera: deja su error y sigue."""
    try:
        return fn(*args)
    except Exception as e:  # noqa: BLE001 - cualquier fallo de una sección se apunta, no se propaga
        return {'error': '%s: %s' % (type(e).__name__, str(e)[:200])} if defecto is None else defecto


def main():
    t0 = time.time()
    eq = seguro(equipo)
    ct = seguro(contenedores)
    # contenedores con red propia (no la del servidor) y en marcha: sus conexiones se miran desde dentro
    en_red = [(c['nombre'], c['_pid']) for c in ct if c.get('_pid') and c.get('red') != 'host'] if isinstance(ct, list) and eq.get('root') and shutil.which('nsenter') else []
    if isinstance(ct, list):
        for c in ct:
            c.pop('_pid', None)
    esc = seguro(escucha)
    ent, sal = seguro(conexiones, esc if isinstance(esc, list) else [], en_red, defecto=([], []))
    data = {
        'lupa_servidor': VERSION, 'generado': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'equipo': eq,
        'parches': seguro(parches, eq.get('so_id', '')), 'escucha': esc, 'entradas': ent, 'salidas': sal, 'cortafuegos': seguro(cortafuegos),
        'ssh': seguro(ssh), 'usuarios': seguro(usuarios), 'contenedores': ct, 'redes_docker': seguro(redes_docker, defecto=[]),
        'servicios': seguro(servicios), 'endurecimiento': seguro(endurecimiento), 'ficheros': seguro(ficheros),
    }
    data['segundos'] = round(time.time() - t0, 1)
    if not eq.get('root'):
        data['aviso'] = 'Ejecutado sin root: faltan procesos de los puertos, la config de SSH y parte de los ficheros.'
    # en ASCII: con el locale C de SSM, un «josé» en una ruta rompería la salida
    json.dump(data, sys.stdout, ensure_ascii=True, separators=(',', ':'))
    sys.stdout.write('\n')


if __name__ == '__main__':
    main()
