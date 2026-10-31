# IAM Auditor

A small Python tool that scans an AWS account and flags risky IAM users.

## What it checks
- **No MFA**: users without a second login factor
- **Stale access keys**: active keys older than a threshold (default 90 days)
- **Admin policies**: users with AdministratorAccess (or similar) attached

## Setup
```bash
git clone <your-repo-url>
cd iam-auditor
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

## Usage
```bash
python3 iam_auditor.py --output summary
python3 iam_auditor.py --output json --key-age-threshold 60
python3 iam_auditor.py --profile myprofile
```

| Option | Meaning | Default |
|---|---|---|
| `--key-age-threshold` | Flag keys older than this many days | 90 (from `.env`) |
| `--output` | `summary` or `json` | summary |
| `--profile` | AWS CLI profile to use | from `.env` |

## Required AWS permissions
Read-only IAM access: `iam:ListUsers`, `iam:ListMFADevices`,
`iam:ListAccessKeys`, `iam:ListAttachedUserPolicies`.

## Tests
```bash
python3 -m pytest -v
```

## Security notes
- Never commit `.env` or AWS credentials (`.env` is in `.gitignore`).
- The tool is read-only. It never changes anything in your account.