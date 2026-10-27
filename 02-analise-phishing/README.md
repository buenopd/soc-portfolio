# Lab 02 — Análise de Phishing

|                      |                                                              |
| -------------------- | ------------------------------------------------------------ |
| **Data**             | AAAA-MM-DD                                                   |
| **Categoria**        | Análise de tráfego / Phishing / SIEM / Detecção / Malware    |
| **Ferramentas**      | ...                                                          |
| **Dificuldade**      | Fácil / Média / Difícil                                      |
| **Fonte do cenário** | (ex.: malware-traffic-analysis.net, exercício de AAAA-MM-DD) |

---

## 1. Resumo executivo

> 3 a 5 linhas, escritas para um gestor que não é técnico: o que aconteceu, qual o impacto e qual a recomendação principal.

## 2. Objetivo

Realizar a triagem de um e-mail de phishing real, como um analista de SOC faria com um e-mail reportado por um usuário: analisar cabeçalhos e autenticação (SPF, DKIM, DMARC), examinar o conteúdo e os links, extrair IOCs, consultar reputação e emitir um veredito com recomendações de resposta.

## 3. Ambiente

- Sistema: Omarchy 
- Ferramentas: less/nvim, eml-analyzer, whois, dig, VirusTotal, urlscan.io
- Amostra: `sample-12152.eml`, do phishing_pot (github.com/rf-peixoto/phishing_pot)
- SHA-256: feac32261add710855cb311d487c15c7da461406a3ef257cac0cc1337f6d2505 

## 4. Execução / Investigação

Descreva o passo a passo do que você fez **e por que fez**. O raciocínio é tão importante quanto o resultado.

### 4.1 [Etapa]

Explicação.

```
comando ou filtro utilizado
```

![Descrição da evidência](./imagens/01-exemplo.png)

### 4.2 [Etapa]

...

## 5. Linha do tempo

| Horário (UTC) | Evento |
|---|---|
| 00:00:00 | ... |

## 6. Indicadores de comprometimento (IOCs)

| Tipo | Valor | Contexto |
|---|---|---|
| IP | `192.0.2[.]10` | Servidor C2 |
| Domínio | `exemplo[.]com` | Download do payload |
| SHA256 | `...` | Anexo malicioso |

> Sempre "desarme" IPs e domínios com `[.]` para não virarem links clicáveis.

## 7. Mapeamento MITRE ATT&CK

| Tática | Técnica | ID | Evidência |
|---|---|---|---|
| Initial Access | Phishing: Spearphishing Attachment | T1566.001 | Seção 4.1 |

## 8. Conclusão e recomendações

- Veredito (ex.: verdadeiro positivo, máquina X comprometida)
- Ações de contenção e correção recomendadas
- Oportunidades de detecção

## 9. Lições aprendidas

O que você aprendeu, o que teve dificuldade e o que faria diferente. Esta seção mostra evolução e é muito bem vista em entrevistas.

## 10. Referências

- [Nome da referência](https://...)
