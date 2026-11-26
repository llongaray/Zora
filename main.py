import argparse
import os
import re
import shlex
import smtplib
import ssl
import subprocess
import time
from pathlib import Path
from email.message import EmailMessage
import paramiko
import yaml
from dotenv import load_dotenv

BASE = Path(__file__).resolve().parent
load_dotenv(BASE / ".env")

def vpn(cfg, profile, action):
    return subprocess.run([cfg["forticlient"], "--cli", "--"+action, "--tunnel", profile], capture_output=True, text=True, check=True, timeout=120).stdout

def connected(cfg, profile):
    return any(line.strip().casefold() == (profile+" :: Connected").casefold() for line in vpn(cfg, profile, "status").splitlines())

def wait_vpn(cfg, profile, state):
    expected = profile + (" :: Connected" if state else " :: Disconnected")
    for _ in range(30):
        if any(line.strip().casefold() == expected.casefold() for line in vpn(cfg, profile, "status").splitlines()):
            return
        time.sleep(3)
    raise TimeoutError("Estado VPN não confirmado: "+profile)

def remote(client, command, report, timeout=900, allowed=(0,)):
    channel = client.get_transport().open_session(timeout=20)
    out, err = bytearray(), bytearray()
    try:
        channel.exec_command(command)
        deadline = time.monotonic()+timeout
        while True:
            if channel.recv_ready(): out.extend(channel.recv(65536))
            if channel.recv_stderr_ready(): err.extend(channel.recv_stderr(65536))
            if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready(): break
            if time.monotonic()>deadline: raise TimeoutError("Comando remoto excedeu prazo; verificar estado antes de repetir")
            time.sleep(.05)
        code=channel.recv_exit_status()
        output=out.decode(errors="replace")
        report.append(f"$ {command}\nExit: {code}\n{output}\n{err.decode(errors='replace')}")
        if code not in allowed: raise RuntimeError(f"Comando retornou {code}")
        return code,output
    finally:
        channel.close()

def inventory(client, report):
    _, raw=remote(client, "dpkg-query -W -f='${Package}\\t${Version}\\t${Status}\\n' 'zabbix-*'", report, allowed=(0,1))
    return {p:v for p,v,s in (line.split("\t",2) for line in raw.splitlines() if line.count("\t")==2) if s=="install ok installed" and p!="zabbix-release"}

def series(version):
    m=re.match(r"^(?:\d+:)?(\d+\.\d+)",version)
    if not m: raise ValueError("Versão desconhecida")
    return m.group(1)

def update(cfg, host, apply, report):
    prefix=host["credentials"]
    with paramiko.SSHClient() as client:
        client.load_system_host_keys()
        client.load_host_keys(str(Path(cfg["known_hosts"]).expanduser()))
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        client.connect(host["ip"],port=host.get("port",22),username=os.environ[prefix+"_USER"],password=os.environ[prefix+"_PASSWORD"],timeout=15,banner_timeout=20,auth_timeout=20,look_for_keys=False,allow_agent=False)
        remote(client,"cat /etc/os-release; df -h / /var",report)
        remote(client,"command -v apt-get && command -v dpkg-query && command -v systemctl",report)
        before=inventory(client,report)
        if not before: return "SEM PACOTES ZABBIX"
        if any(not (p in ("zabbix-agent","zabbix-agent2") or p.startswith("zabbix-agent2-plugin-")) for p in before):
            return "BLOQUEADO: componentes fora do escopo de agentes"
        services=[p for p in ("zabbix-agent","zabbix-agent2") if p in before]
        if apply: remote(client,"sudo -n apt-get update",report)
        targets={}
        for package,version in before.items():
            if not re.fullmatch(r"[a-z0-9+.-]+",package): raise ValueError("Pacote inválido")
            _,policy=remote(client,"LC_ALL=C apt-cache policy "+shlex.quote(package),report)
            m=re.search(r"^\s*Candidate:\s*(\S+)",policy,re.M)
            if not m or m.group(1)=="(none)": raise RuntimeError("Sem candidato: "+package)
            candidate=m.group(1)
            if series(version)!=series(candidate): raise RuntimeError("Mudança de série bloqueada")
            code,_=remote(client,"dpkg --compare-versions "+shlex.quote(candidate)+" gt "+shlex.quote(version),report,allowed=(0,1))
            if code==0: targets[package]=candidate
        if not targets: return "ATUALIZADO NO REPOSITÓRIO CONFIGURADO"
        args=" ".join(shlex.quote(p+"="+v) for p,v in targets.items())
        _,simulation=remote(client,"LC_ALL=C apt-get -s --no-remove install --only-upgrade "+args,report)
        if re.search(r"^Remv ",simulation,re.M): raise RuntimeError("Remoção prevista")
        if not apply: return "SIMULAÇÃO: atualização disponível"
        for service in services: remote(client,"systemctl is-active "+service,report)
        remote(client,"sudo -n env DEBIAN_FRONTEND=noninteractive apt-get -y --no-remove -o Dpkg::Options::=--force-confold install --only-upgrade "+args,report)
        after=inventory(client,report)
        if any(after.get(p)!=v for p,v in targets.items()): raise RuntimeError("Versão final divergente")
        for service in services: remote(client,"systemctl is-active "+service,report)
        return "ATUALIZADO E VALIDADO"

def email(cfg,host,status,report):
    msg=EmailMessage()
    msg["From"]=os.environ["SMTP_USER"]
    msg["To"]=", ".join(cfg["recipients"])
    msg["Subject"]=f"[Zora] {host['name']} - {status}"
    msg.set_content("\n".join(report))
    context=ssl.create_default_context()
    security=os.getenv("SMTP_SECURITY","starttls")
    if security not in ("ssl","starttls"): raise ValueError("SMTP exige TLS")
    port=int(os.getenv("SMTP_PORT","587"))
    cls=smtplib.SMTP_SSL if security=="ssl" else smtplib.SMTP
    kwargs={"context":context} if security=="ssl" else {}
    with cls(os.environ["SMTP_HOST"],port,timeout=30,**kwargs) as smtp:
        if security=="starttls": smtp.ehlo(); smtp.starttls(context=context); smtp.ehlo()
        smtp.login(os.environ["SMTP_USER"],os.environ["SMTP_PASSWORD"])
        smtp.send_message(msg)

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--apply",action="store_true")
    args=parser.parse_args()
    cfg=yaml.safe_load((BASE/"config.yaml").read_text(encoding="utf-8"))
    apply=args.apply and cfg.get("apply") is True
    logs=BASE/"logs"
    logs.mkdir(exist_ok=True)
    pending=[]
    for host in cfg["hosts"]:
        if host["vpn"] not in cfg["vpn"]: raise ValueError("VPN não cadastrada")
    try:
        for name,settings in cfg["vpn"].items():
            hosts=[h for h in cfg["hosts"] if h["vpn"]==name]
            if not hosts: continue
            profile=settings["profile"]
            owned=False
            failure=None
            try:
                try:
                    if connected(cfg,profile): raise RuntimeError("VPN já ativa; desconecte antes de executar")
                    owned=True
                    vpn(cfg,profile,"connect")
                    wait_vpn(cfg,profile,True)
                except Exception as exc: failure=str(exc)
                for host in hosts:
                    report=[f"Host: {host['name']} | {host['ip']} | VPN: {name}",f"Aplicação: {apply}"]
                    try:
                        if failure: raise RuntimeError(failure)
                        status=update(cfg,host,apply,report)
                    except Exception as exc:
                        status="FALHA"
                        report.append(f"{type(exc).__name__}: {exc}")
                    report.insert(0,"Resultado: "+status)
                    filename=re.sub(r"[^a-zA-Z0-9_-]","_",host["name"])+"_"+str(time.time_ns())+".txt"
                    (logs/filename).write_text("\n".join(report),encoding="utf-8")
                    pending.append((host,status,report))
                    print(host["name"],status)
            finally:
                if owned:
                    vpn(cfg,profile,"disconnect")
                    wait_vpn(cfg,profile,False)
    finally:
        for host,status,report in pending:
            try: email(cfg,host,status,report)
            except Exception as exc: print("Falha SMTP; relatório local preservado:",host["name"],type(exc).__name__)

if __name__=="__main__":
    main()
