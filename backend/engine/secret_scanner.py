"""
Secret & API Key Exposure Scanner
Mengesan credentials dan API keys yang terdedah dalam kod sumber
"""

import re

SECRET_PATTERNS = [
    {
        "type": "SUPABASE_KEY",
        "pattern": r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}",
        "description": "Supabase JWT key (anon/service) terdedah dalam kod.",
        "recommendation": "Pindahkan ke environment variable. Jangan hardcode dalam kod frontend atau backend.",
    },
    {
        "type": "FIREBASE_CONFIG",
        "pattern": r"apiKey\s*:\s*[\"']AIza[A-Za-z0-9_-]{35}[\"']",
        "description": "Firebase API key terdedah dalam konfigurasi.",
        "recommendation": "Hadkan Firebase key menggunakan Firebase Security Rules dan domain restriction.",
    },
    {
        "type": "STRIPE_SECRET",
        "pattern": r"sk_live_[A-Za-z0-9]{24,}",
        "description": "Stripe secret key (sk_live_) terdedah — boleh digunakan untuk caj kad kredit.",
        "recommendation": "SEGERA revoke key ini di Stripe dashboard. Guna environment variable.",
    },
    {
        "type": "STRIPE_PUBLIC",
        "pattern": r"pk_live_[A-Za-z0-9]{24,}",
        "description": "Stripe publishable key (pk_live_) terdedah.",
        "recommendation": "Walaupun public key, pastikan ia tidak dicommit dalam repo private.",
    },
    {
        "type": "OPENAI_KEY",
        "pattern": r"sk-[A-Za-z0-9]{32,}",
        "description": "OpenAI/Anthropic API key terdedah — boleh digunakan untuk caj akaun anda.",
        "recommendation": "SEGERA revoke key ini. Guna environment variable dan jangan commit ke git.",
    },
    {
        "type": "AWS_ACCESS_KEY",
        "pattern": r"AKIA[A-Z0-9]{16}",
        "description": "AWS Access Key ID terdedah — boleh digunakan untuk akses AWS resources anda.",
        "recommendation": "SEGERA deactivate key di AWS IAM. Semak CloudTrail untuk aktiviti mencurigakan.",
    },
    {
        "type": "AWS_SECRET_KEY",
        "pattern": r"(?i)(aws_secret_access_key|aws_secret)\s*[=:]\s*[\"']?[A-Za-z0-9/+]{40}[\"']?",
        "description": "AWS Secret Access Key terdedah.",
        "recommendation": "SEGERA rotate credentials di AWS IAM Console.",
    },
    {
        "type": "HARDCODED_ENV_VALUE",
        "pattern": r"(?i)(NEXT_PUBLIC_|REACT_APP_|VITE_)[A-Z_]+\s*=\s*[\"'][^\"']{8,}[\"']",
        "description": "Environment variable dengan nilai hardcoded dalam kod frontend bundle.",
        "recommendation": "Guna .env file dan pastikan .env ada dalam .gitignore.",
    },
    {
        "type": "GENERIC_SECRET",
        "pattern": r"(?i)(secret_key|private_key|client_secret)\s*[=:]\s*[\"'][^\"']{12,}[\"']",
        "description": "Secret key atau private key terdedah dalam kod.",
        "recommendation": "Pindahkan ke environment variable atau secrets manager.",
    },
    {
        "type": "GITHUB_TOKEN",
        "pattern": r"gh[pousr]_[A-Za-z0-9]{36,}",
        "description": "GitHub Personal Access Token terdedah.",
        "recommendation": "SEGERA revoke token di GitHub Settings. Guna environment variable.",
    },
]


def scan_secrets(file_content: str, filename: str) -> list[dict]:
    """Scan kandungan fail untuk secrets dan API keys yang terdedah."""
    findings = []
    lines = file_content.splitlines()

    for rule in SECRET_PATTERNS:
        for i, line in enumerate(lines, start=1):
            if re.search(rule["pattern"], line):
                # Redact nilai sebenar dari output
                findings.append({
                    "type": rule["type"],
                    "severity": "CRITICAL",
                    "line": i,
                    "line_hint": f"{filename}:{i} → {line.strip()[:60]}...",
                    "description": rule["description"],
                    "recommendation": rule["recommendation"],
                    "simple_explanation": f"Kunci rahsia atau kata laluan ditemui dalam fail `{filename}` baris {i}. Sesiapa yang ada akses ke kod ini boleh gunakan kunci tersebut untuk akses sistem anda.",
                })

    return findings
