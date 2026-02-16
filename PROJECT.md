# SoftSwitch Project

## Repository
- **URL:** https://github.com/dayat81/SoftSwitch.git
- **Branch:** master

## Credentials
- **GitHub Token:** (see local env or GitHub settings)
- **Note:** Token stored separately for security

## Latest Commit
- **Hash:** 8549c91
- **Message:** Add web dashboard with service grouping and classification
- **Files:**
  - web_server.py
  - gunicorn.conf.py
  - static/index.html

## Setup
```bash
cd /home/dayat/SoftSwitch
git config user.email "dayat@raspi"
git config user.name "Dayat"
```

## Service Status
```bash
sudo systemctl status softswitch-web
```

## Access
- Dashboard: http://raspi:5000
- API: http://raspi:5000/api/stats
