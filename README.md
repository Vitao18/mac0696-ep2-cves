# EP2 — Cibersegurança e Privacidade (MAC0696 / IME-USP)

Estudo, exploração e correção de **duas CVEs (2025+)**, em ambiente 100% local e isolado.

## Integrantes do trio

| Nome | Nº USP | E-mail |
|------|--------|--------|
| _(preencher)_ | | |
| _(preencher)_ | | |
| _(preencher)_ | | |

## CVEs escolhidas

| CVE | Produto | Classe | Papel na entrega |
|-----|---------|--------|------------------|
| **CVE-2025-49596** | MCP Inspector (`@modelcontextprotocol/inspector` < 0.14.1) | RCE não-autenticado via CORS/DNS-rebinding (CWE-306) | **Demo ao vivo** |
| **CVE-2025-27636** | Apache Camel (3.10–3.22.3, 4.8.0–4.8.4, 4.10.0–4.10.1) | RCE via bypass do filtro de headers por case-sensitivity | **Só no PDF** (reproduzível) |

## Estrutura do repositório

```
.
├── README.md                          ← este arquivo
├── mcp-inspector-cve-2025-49596/      ← demo ao vivo (containers)
│   ├── README.md                      ← roteiro passo a passo da demo
│   ├── Dockerfile                     ← Inspector vulnerável/corrigido (ARG de versão)
│   ├── docker-compose.yml             ← versão VULNERÁVEL (0.14.0) + site atacante
│   ├── docker-compose.fixed.yml       ← versão CORRIGIDA (0.14.1), mesmo ataque falha
│   ├── attacker/                      ← página maliciosa (CORS → RCE), comentada
│   ├── exploit/exploit.sh             ← PoC reproduzível via curl
│   ├── evidence/                      ← volume montado; a prova do RCE cai aqui
│   └── docs/                          ← RCA (no código-fonte) + workarounds
├── apache-camel-cve-2025-27636/       ← reprodução mínima (só PDF)
│   ├── README.md
│   ├── route/                         ← rota Camel vulnerável (platform-http → exec)
│   ├── exploit/poc.sh                 ← bypass por case-sensitivity do header
│   └── docs/                          ← RCA no DefaultHeaderFilterStrategy + patch
└── pdf/relatorio.md                   ← rascunho do PDF (5–10 págs), converter depois
```

## Regras de segurança desta entrega

- **Tudo roda em containers locais.** Nenhum alvo externo é tocado. As portas são publicadas
  apenas em `127.0.0.1` (loopback), nunca na LAN.
- O "RCE" dos PoCs só escreve um arquivo de prova (`id`, `hostname`) num volume montado.
  Nenhum payload destrutivo, nenhuma conexão de saída.
- **Créditos:** os PoCs aqui foram escritos do zero a partir das *advisories* oficiais e das
  divulgações públicas dos pesquisadores. As fontes estão creditadas em cada
  `docs/root-cause-analysis.md` e no PDF. Reaproveitar PoC de terceiro sem crédito é plágio
  pela regra da disciplina.

## Pré-requisitos

- Docker + Docker Compose v2 (`docker compose`).
- Um navegador (Chrome/Firefox) para a parte CORS da demo.
- (Opcional, só p/ a reprodução do Camel) `jbang` ou a imagem Docker fornecida.
