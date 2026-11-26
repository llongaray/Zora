# Zora

Gerenciador de atualização Zabbix via SSH e FortiClient VPN para Windows.

Instale Python 3.10+, execute `pip install -r requirements.txt`, copie `.env.example` para `.env` e `config.example.yaml` para `config.yaml`. Cadastre chaves SSH verificadas em known_hosts. Execute `python main.py` para simular; para aplicar, habilite `apply: true` e execute `python main.py --apply`.

Suporte inicial: agentes Zabbix em Debian/Ubuntu, mesma série de versão, repositórios existentes. Server/proxy, Docker e RPM não suportados. FortiClient CLI e SMTP precisam ser validados localmente. Não há rollback automático. Não publique credenciais ou configuração real.
