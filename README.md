# 🔐 frappe-safe-scan  
### Static Security Scanner for Frappe & ERPNext Python Codebases  
A lightweight AST-based security analyzer to automatically detect:

- unsafe `eval` / `exec`  
- SQL injection patterns  
- hardcoded API keys / secrets  
- unsafe subprocess usage  
- string-concatenated queries  

This tool is built to help teams maintain secure, high-quality code across Frappe apps and ERPNext customizations.

---

## 🚀 Features
✔ No dependencies except Python  
✔ AST-based → fast, accurate, explainable  
✔ Runs in CI/CD (GitHub Actions included)  
✔ Add as a pre-commit hook  
✔ Ideal for engineering teams working with Frappe/ERPNext  

---

## 📦 Installation

