# WinAudit

Auditoria de segurança do Windows pela linha de comando. Verifica a configuração da máquina e os programas instalados, dá uma **nota de 0 a 100** e diz **como corrigir** cada problema. Gera saída no terminal, relatório HTML e JSON.

> **O scan é somente leitura**: ele não altera nada no seu PC. As correções aparecem como instruções ou comandos para você copiar. O único comando que muda algo é o `python -m winaudit update`, que atualiza programas pelo winget e sempre pede confirmação antes.

> **Aviso**: o WinAudit faz uma checagem básica de configuração e de vulnerabilidades conhecidas. Ele **não é antivírus**, não detecta malware já instalado e não substitui uma auditoria profissional. Uma nota alta indica que os pontos verificados estão em ordem, não que o computador está totalmente seguro. A busca de CVEs depende da base do NVD e pode ter falsos positivos ou deixar programas de fora.

## Começo rápido

Abra o **PowerShell como administrador** ou **CMD como administrador** (menu Iniciar → digite "PowerShell" ou "CMD" → botão direito → *Executar como administrador*) e rode:

```powershell
git clone https://github.com/luizpetry/winaudit.git
cd winaudit
pip install -e .
python -m winaudit --cve --html relatorio.html
start relatorio.html
```

Pronto: o resultado aparece no terminal e o relatório abre no navegador. Para atualizar os programas vulneráveis que ele encontrar:

```powershell
python -m winaudit update
```

## Passo a passo

### 1. Pré-requisitos

- **Windows 10 ou 11.**
- **Python 3.10 ou mais novo.** Confira com `python --version`. Se não tiver, instale com:
  ```powershell
  winget install Python.Python.3.12
  ```
  Feche e abra o terminal de novo depois de instalar.
- **Git** (só para baixar o projeto): `winget install Git.Git`. Se preferir, baixe o ZIP pelo botão *Code → Download ZIP* do GitHub e extraia.

### 2. Instalar

```powershell
git clone https://github.com/luizpetry/winaudit.git
cd winaudit
pip install -e .
```

Isso instala a única dependência (`psutil`). Neste guia os comandos usam `python -m winaudit`, que funciona em qualquer PC.

> **Atalho opcional:** o `pip install` também cria o comando curto `winaudit` (ex.: `winaudit update`). Se ele der `'winaudit' não é reconhecido como um comando interno ou externo` (Prompt de Comando) ou `O termo 'winaudit' não é reconhecido` (PowerShell), a pasta de scripts do Python não está no PATH. Isso é comum com o Python da Microsoft Store. Continue usando `python -m winaudit`, ou, para o atalho funcionar, adicione ao PATH a pasta que o `pip install` indicou no aviso "*is installed in '...' which is not on PATH*" (Configurações → Sistema → Sobre → Configurações avançadas do sistema → Variáveis de Ambiente → `Path` do usuário) e abra o terminal de novo.

### 3. Rodar o scan

**Rode como administrador** para resultados completos. Sem admin, o Windows esconde algumas informações (comandos das tarefas agendadas, detalhes do BitLocker) e o relatório avisa o que ficou de fora.

| Quero… | Comando | Tempo |
|---|---|---|
| Ver a configuração do Windows | `python -m winaudit` | segundos |
| …e gerar relatório HTML | `python -m winaudit --html relatorio.html` | segundos |
| …e procurar vulnerabilidades nos programas comuns | `python -m winaudit --cve --html relatorio.html` | 1 a 3 min |
| …e procurar vulnerabilidades em **todos** os programas | `python -m winaudit --cve-auto --html relatorio.html` | 10 a 15 min na 1ª vez |

Para abrir o relatório: `start relatorio.html`.

Outras opções:

```powershell
python -m winaudit --json relatorio.json      # salva em JSON (para comparar ao longo do tempo)
python -m winaudit --json                     # JSON direto no terminal
python -m winaudit --only firewall,defender   # só alguns checks (veja os nomes com --list)
python -m winaudit --list                     # lista os checks disponíveis
python -m winaudit -v                         # mostra todos os detalhes no terminal
```

### 4. Entender o resultado

Cada item tem um status:

| Status | Significado |
|---|---|
| **Falha** | Problema de segurança. Desconta da nota conforme a severidade. |
| **Alerta** | Algo que merece atenção. Desconta metade. |
| **OK** | Verificado e em ordem. |
| **Info** | Só informação para você conferir (ex.: lista de programas que iniciam com o Windows). Não desconta. |

Nos programas com vulnerabilidades (CVEs), o relatório mostra:

- **Quantas CVEs** afetam a versão instalada e a maior nota CVSS (gravidade teórica, de 0 a 10).
- **Quais já foram exploradas em ataques reais**, marcadas como `[EXPLORADA]` ou `[EXPLORADA, RANSOMWARE]`. **Essas são as mais urgentes.**
- **Riscos de manter assim**: como as falhas podem ser usadas contra você (visitar um site, abrir um arquivo, clonar um repositório…) e o que um atacante conseguiria (executar código no seu PC, ler ou alterar dados…).

### 5. Corrigir os problemas

Cada item traz o *Como corrigir*, com um botão **Copiar** no relatório HTML. As correções mais comuns:

**Programas vulneráveis ou desatualizados.** O `python -m winaudit update` atualiza pelo `winget`, que já vem no Windows:

```powershell
python -m winaudit update --dry-run     # só mostra o que seria atualizado (não instala nada)
python -m winaudit update               # atualiza só os programas com vulnerabilidades conhecidas
python -m winaudit update --all         # atualiza tudo que tiver atualização, menos jogos
python -m winaudit update --all --games # tudo mesmo, incluindo jogos e launchers
```

Como funciona:
- **Por padrão, só os vulneráveis.** Ele faz a busca de CVEs (usando o cache do último scan, se houver) e atualiza apenas os programas com falhas conhecidas, começando pelos mais graves. Para incluir os achados pela descoberta automática, use `python -m winaudit update --cve-auto`.
- **Jogos ficam de fora.** Jogos e launchers (Steam, Epic, EA app, Ubisoft Connect, Battle.net, Riot…) já se atualizam sozinhos pelo próprio launcher. São reconhecidos pelo fabricante, pela pasta de instalação e pelo ID no winget. Use `--games` para incluí-los.
- **Sempre pede confirmação.** Mostra a lista antes e só instala depois que você confirmar. Use `-y` para pular a pergunta (útil em scripts).
- **Vulneráveis que o winget não atualiza** aparecem separados, com o comando pronto para desinstalar caso você não use o programa.
- Programas fixados com `winget pin add <ID>` não são atualizados no `--all`.

Dicas:
- Feche os programas antes de atualizar. Algumas atualizações pedem confirmação do Windows (UAC). Rodar o terminal como administrador reduz os pedidos.
- Se preferir usar o winget direto: `winget upgrade` lista as atualizações, `winget upgrade --id <ID>` atualiza um programa e `winget upgrade --all` atualiza tudo (incluindo jogos).
- Alguns programas não aparecem no winget (jogos da Steam, VMware, alguns launchers). Atualize esses pelo próprio programa ou pelo site oficial.
- Se uma atualização der problema, quase sempre dá para voltar: `winget install --id <ID> --version <versão antiga>`.

**Programas que você não usa.** Desinstalar é melhor que atualizar: programa parado continua vulnerável se algo o abrir (um link, um arquivo associado, outro app).

```powershell
winget uninstall Google.Chrome   # use o nome ou ID que aparece em "winget list"
```

Ou pelo menu: Configurações → Aplicativos → Aplicativos instalados.

**Atualizações do Windows.** O winget não atualiza o sistema. Use Configurações → Windows Update → Verificar atualizações.

**Configurações do Windows** (firewall, UAC, BitLocker, SMBv1…). Siga o *Como corrigir* de cada item. O WinAudit nunca muda essas configurações sozinho.

### 6. Verificar de novo

Depois de corrigir, rode o mesmo comando outra vez e compare a nota:

```powershell
python -m winaudit --cve --html relatorio.html
```

As consultas de CVE ficam em cache por 24h para cada versão de programa. Um programa atualizado tem versão nova, então é consultado de novo na hora.

Para acompanhar ao longo do tempo, salve um JSON com data:

```powershell
python -m winaudit --cve --json "relatorio-$(Get-Date -Format yyyy-MM-dd).json"
```

## O que é verificado

| Check | O que olha |
|---|---|
| `firewall` | Os 3 perfis do Firewall do Windows ligados e bloqueando entrada por padrão |
| `defender` | Antivírus ativo, proteção em tempo real, idade das assinaturas, proteção contra violação (detecta antivírus de terceiros) |
| `uac` | UAC ligado e pedindo confirmação |
| `smb_rdp` | SMBv1 (WannaCry), Área de Trabalho Remota e NLA |
| `accounts` | Conta Convidado, Administrador interno, membros do grupo Administradores, uso diário com conta admin |
| `ports` | Serviços ouvindo na rede (Telnet, FTP, VNC, bancos de dados, Docker API…) |
| `startup` | Chaves Run/RunOnce, pasta Inicializar e tarefas agendadas. Detecta padrões de malware (PowerShell codificado, `mshta`, `certutil`, executáveis em `%TEMP%`) |
| `updates` | Idade da última atualização e atualizações de segurança pendentes |
| `bitlocker` | Criptografia do disco do sistema (mais severo em notebooks) |
| `software` | Inventário e programas sem suporte do fabricante (Flash, Python 2, Java 6/7…) |
| `cve` *(opcional)* | Vulnerabilidades conhecidas (CVEs) nos programas instalados. Veja abaixo |

## Busca de vulnerabilidades (CVEs)

Há dois modos:

| | `--cve` | `--cve-auto` |
|---|---|---|
| Programas verificados | Os ~60 programas comuns do catálogo (navegadores, compactadores, acesso remoto, VPN, ferramentas de dev, virtualização…) que estiverem instalados | O catálogo + qualquer outro programa instalado que dê para associar a um produto do NVD |
| O que é enviado ao NVD | Fornecedor/produto/versão dos programas do catálogo | Também o **nome** dos demais programas instalados, para procurá-los no dicionário do NVD |
| Tempo (sem chave de API) | 1 a 3 min | 10 a 15 min na primeira vez; depois usa o cache |

### Deixar mais rápido com uma chave de API (grátis)

Sem chave, o NVD limita a ~5 consultas a cada 30 segundos. Com chave, o `--cve-auto` cai de ~15 min para ~1-2 min.

1. Peça a chave em https://nvd.nist.gov/developers/request-an-api-key (chega por e-mail).
2. Configure no PowerShell:
   ```powershell
   setx NVD_API_KEY "sua-chave-aqui"
   ```
3. Feche e abra o terminal. O WinAudit passa a usar a chave sozinho.

### Como funciona

- **Filtro local.** Uma CVE só conta se a faixa de versões vulneráveis cobre a versão instalada e se ela não for exclusiva de outra plataforma (Android, macOS…).
- **Falhas exploradas.** As CVEs são cruzadas com o [catálogo KEV da CISA](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), a lista pública de falhas que comprovadamente já foram usadas em ataques reais. Essas aparecem primeiro e elevam a gravidade para no mínimo alta, ou crítica se usadas por ransomware. O catálogo é baixado inteiro, sem enviar nada sobre o PC.
- **Riscos.** As CVEs de cada programa são agrupadas por como podem ser exploradas e pelo pior efeito possível. A classificação usa a descrição de cada CVE e o vetor CVSS, então algumas caem em "outros cenários".
- **Identificação automática (`--cve-auto`).** É conservadora: só aceita um produto do NVD se o fabricante bater com o campo *Publisher* do programa e se o nome corresponder. O que não for identificado com segurança aparece como "não identificado" e não é verificado. CVEs encontradas assim indicam o produto do NVD usado, para você conferir.
- **Privacidade.** Programas cujo nome contém o seu nome de usuário ou o nome do PC nunca são enviados. Drivers, runtimes, redistribuíveis e atualizações (KB) são ignorados.
- **Cache** em `~/.winaudit/cache`: CVEs e catálogo KEV por 24h, identificação de programas por 30 dias. Pode apagar a pasta à vontade.

## Nota

Cada falha desconta pela severidade: crítica 25, alta 15, média 8, baixa 3. Alertas descontam metade. Itens informativos não descontam. Letras: A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, F < 60.

Código de saída: `0` sem falhas, `1` se houver alguma falha. Dá para usar em scripts e no Agendador de Tarefas.

## Perguntas frequentes

**Minha nota ficou muito baixa. É grave?**
Olhe primeiro os itens marcados como `[EXPLORADA]` e as falhas críticas. Um único programa muito desatualizado (um navegador, por exemplo) pode derrubar a nota sozinho. Atualizar ou desinstalar esse programa costuma resolver a maior parte.

**Apareceram milhares de CVEs num programa. Está certo?**
Pode estar. Navegadores corrigem dezenas de falhas por mês, então uma versão com um ano de atraso acumula muitas. O número importa menos do que quantas já foram exploradas e quais são os riscos listados.

**Preciso rodar como administrador?**
Não é obrigatório, mas sem admin alguns checks ficam limitados. O relatório diz o que ficou de fora.

**O WinAudit envia meus dados para algum lugar?**
Sem `--cve`/`--cve-auto`, nada sai do PC. Com `--cve`, só fornecedor/produto/versão dos programas do catálogo vão para a API pública do NVD. Com `--cve-auto`, também os nomes dos outros programas, com as exceções da seção *Privacidade*. Os relatórios ficam só no seu PC.

**Apareceu um falso positivo.**
Abra uma issue com o nome do programa, a versão e a CVE. Se o programa foi identificado pelo `--cve-auto`, inclua também o produto do NVD que aparece no relatório.

## Desenvolvimento

### Testes

```powershell
python -m unittest discover -s tests -t .
```

### Adicionando um programa ao catálogo de CVEs

Adicione uma linha em `CATALOG` (`winaudit/checks/cve.py`) com a regex do nome do programa (como aparece em *Aplicativos instalados*) e o fornecedor/produto do CPE. Procure o CPE em https://nvd.nist.gov/products/cpe/search.

### Adicionando um check

Crie um arquivo em `winaudit/checks/`. Ele é carregado automaticamente:

```python
from ..models import Severity, failed, passed
from . import check

@check("meu_check", "Categoria", order=200)
def meu_check(ctx):
    if algo_errado:
        return [failed("meu_check.x", "Titulo", Severity.MEDIUM, "Explicacao", "Como corrigir")]
    return [passed("meu_check.x", "Tudo certo")]
```

## Licença

[MIT](LICENSE)
