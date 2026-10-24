# Como contribuir com o NetWatch

Obrigado pelo interesse! O projeto é pequeno de propósito: Python puro, sem dependências externas, rodando na rede local de quem usa.

## Antes de abrir uma issue

- Verifique se já existe uma issue parecida.
- Para **falhas de segurança**, não abra issue pública: descreva o problema em particular para o mantenedor (veja a seção de segurança abaixo).

## Ambiente de desenvolvimento

Requisitos: Python 3.10 ou mais novo. Nada de `pip install` — só biblioteca padrão.

```bash
git clone https://github.com/YuriPHB/netwatch-dns.git
cd netwatch-dns

python selftest.py      # roda tudo em portas altas, sem admin
python app.py --demo    # sobe o painel com dados falsos
```

O `selftest.py` cobre: parser DNS (UDP e TCP), banco, login/senha, sessões, auditoria, CSV e troca de senha. **Ele precisa passar antes de qualquer pull request.**

## Enviando mudanças

1. Faça um fork e crie um branch com nome descritivo: `git checkout -b feat/bloqueio-de-sites`.
2. Mantenha o escopo pequeno: um PR = uma mudança.
3. Rode `python selftest.py` e, se mexeu na interface, confira no navegador (desktop e celular).
4. Abra o PR descrevendo **o problema** e **a solução**, com prints se for visual.

Padrões do código:

- Python com `from __future__ import annotations`, tipagem simples e nomes em português quando fizer sentido para o domínio.
- Sem dependências de terceiros (isso é uma promessa do projeto).
- Funções de rede/DB nunca podem derrubar o processo principal: trate exceções.
- Textos de interface em português, sem jargão.

## Ideias de contribuição

- Listas de bloqueio (estilo controle parental) direto no DNS.
- Alertas (Telegram/e-mail) quando um aparelho acessar domínio da lista.
- Relatórios por período/semana.
- Suporte a DoH próprio, para capturar navegadores que ignoram o DNS do sistema.
- Tradução da interface (EN/ES).

## Segurança

Este projeto manipula dados sensíveis (histórico de navegação da rede). Ao contribuir:

- Nunca commite `netwatch.db`, certificados ou senhas.
- Senhas só como hash (`auth.py`); nunca introduza comparação de senha em texto puro.
- Toda rota nova do painel precisa passar por sessão válida e, se for relevante, gerar evento de auditoria.
- Vulnerabilidades: relate em particular ao mantenedor antes de divulgar.
