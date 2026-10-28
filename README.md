# 🛡️ SOC Portfolio — Blue Team Labs

Olá! Me chamo **Pedro Bueno de Carvalho**, estudante do curso técnico em Cibersegurança na FIAP, com foco em **operações de segurança (SOC)**, detecção e resposta a incidentes.

Este repositório reúne laboratórios práticos que desenvolvi para aplicar o que estudo: análise de tráfego, triagem de phishing, monitoramento com SIEM, criação de regras de detecção e análise básica de malware. Cada lab é documentado no formato de um relatório técnico, com evidências e mapeamento no **MITRE ATT&CK**.

📫 [LinkedIn](https://www.linkedin.com/in/pdbcarv) · ✉️ pdbcarvalho@hotmail.com

---

## 📂 Laboratórios

| #   | Lab                                                      | Ferramentas                                | Status       |
| --- | -------------------------------------------------------- | ------------------------------------------ | ------------ |
| 01  | [Análise de tráfego de rede](./01-analise-trafego/)      | Wireshark                                  | ✅ Concluído  |
| 02  | [Análise de e-mail de phishing](./02-analise-phishing/)  | Análise de cabeçalhos, VirusTotal, URLScan | ✅ Concluido  |
| 03  | [Home lab de SOC com Wazuh](./03-homelab-wazuh/)         | Wazuh, Sysmon, Atomic Red Team, KVM        | 🔲 Planejado |
| 04  | [Regras de detecção customizadas](./04-regras-deteccao/) | Wazuh rules, MITRE ATT&CK                  | 🔲 Planejado |
| 05  | [Triagem estática de malware](./05-triagem-malware/)     | strings, PE analysis, VirusTotal           | 🔲 Planejado |

> Legenda: 🔲 Planejado · 🟡 Em andamento · ✅ Concluído

---

## 🧰 Ambiente

- **Host:** Linux (Arch / Omarchy)
- **Virtualização:** KVM / QEMU com virt-manager
- **Rede dos labs:** rede virtual isolada, sem acesso à rede doméstica

## 📐 Padrão dos relatórios

Todos os labs seguem a mesma estrutura ([template](./templates/TEMPLATE-RELATORIO.md)):
objetivo → ambiente → execução → evidências → conclusão → MITRE ATT&CK → lições aprendidas.

## ⚠️ Aviso

Todo o conteúdo é educacional e foi produzido em ambiente controlado e isolado. Nenhuma amostra de malware é armazenada neste repositório; apenas hashes e indicadores (IOCs) são publicados, com domínios e IPs maliciosos "desarmados" (ex.: `evil[.]com`, `192.0.2[.]10`).
