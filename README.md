# 🔐 DevSecOps CI/CD Pipeline

[![Pipeline Status](https://github.com/YOUR_USERNAME/devsecops-pipeline/actions/workflows/devsecops.yml/badge.svg)](https://github.com/YOUR_USERNAME/devsecops-pipeline/actions/workflows/devsecops.yml)
[![Security](https://img.shields.io/badge/security-5%20gates-green)](https://github.com/YOUR_USERNAME/devsecops-pipeline/security)

A complete DevSecOps pipeline enforcing **5 automated security gates** on every commit. Deployment is blocked if any gate finds a critical issue.

## 🏗️ Pipeline Architecture

```
Code Push → Gate 1: SAST (Semgrep+Bandit) → Gate 2: Deps (Trivy+pip-audit)
         → Gate 3: Secrets (Gitleaks)      → Gate 4: Container (Trivy)
         → Gate 5: IaC (Checkov)           → Build → ECR → Deploy EC2
```

## 🐛 Intentional Vulnerabilities (Demo)

| Gate | Vulnerability in `app/app.py` | Tool That Catches It |
|------|-------------------------------|----------------------|
| SAST | SQL injection (string concat) | Bandit + Semgrep |
| SAST | `eval(user_input)` | Semgrep |
| SAST | `subprocess.run(shell=True)` | Bandit |
| Secrets | Hardcoded AWS secret key | Gitleaks |
| Dep Scan | `requests==2.18.0` (CVE-2018-18074) | Trivy + pip-audit |
| Container | Old package CVEs in image | Trivy |
| IaC | Running as root, no HEALTHCHECK | Checkov |

## 🔧 Tools

| Tool | Purpose | License |
|------|---------|---------|
| Semgrep OSS | Multi-language SAST | LGPL |
| Bandit | Python SAST | Apache 2.0 |
| Trivy | Container + dep scanning | Apache 2.0 |
| pip-audit | Python CVE scanning | Apache 2.0 |
| Gitleaks | Secrets detection | MIT |
| Checkov | IaC scanning | Apache 2.0 |

## 📸 Screenshots

_Add screenshots to `docs/screenshots/` after running the pipeline_

- `pipeline-failing.png` — Vulnerable app blocking all gates
- `pipeline-passing.png` — Secure app passing all gates
- `security-tab.png` — GitHub Security tab with SARIF findings

## ⚙️ GitHub Secrets Required

| Secret | Value |
|--------|-------|
| `AWS_ACCESS_KEY_ID` | IAM user key |
| `AWS_SECRET_ACCESS_KEY` | IAM user secret |
| `AWS_REGION` | `us-east-1` |
| `ECR_REGISTRY` | `123456789.dkr.ecr.us-east-1.amazonaws.com` |
| `ECR_REPOSITORY` | `devsecops-demo-app` |
| `EC2_HOST` | EC2 public IP |
| `EC2_SSH_KEY` | Private key contents |
| `DISCORD_WEBHOOK` | Discord channel webhook URL |

## 💬 Interview Answer

> "I built a DevSecOps pipeline that enforces 5 security gates on every commit — static analysis, dependency scanning, secrets detection, container scanning, and IaC scanning. If any gate finds a critical issue, deployment is blocked. I intentionally added vulnerable code to show each gate catching a real finding. Shift-left security in practice."
