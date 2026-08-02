from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent
failures: list[str] = []

for path in ROOT.rglob('*.py'):
    try:
        ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
    except SyntaxError as exc:
        failures.append(f'{path.relative_to(ROOT)}: {exc}')

main_source = (ROOT / 'main.py').read_text(encoding='utf-8')
for required in [
    '/api/password-reset/request',
    '/api/password-reset/verify',
    '/api/password-reset/complete',
    'update_user_by_id',
    'hmac.compare_digest',
    'password_reset_audit',
]:
    if required not in main_source:
        failures.append(f'main.py is missing required recovery element: {required}')

for forbidden in ['SUPABASE_SERVICE_ROLE_KEY=', 'SMTP_PASSWORD=']:
    for candidate in [ROOT / '.env.backend.example']:
        content = candidate.read_text(encoding='utf-8')
        if forbidden in content and 'PASTE_' not in content.split(forbidden, 1)[1].splitlines()[0]:
            failures.append(f'{candidate.name} appears to contain a real secret')

migration = ROOT / 'sql' / '20260730_password_recovery_backend.sql'
if not migration.exists():
    failures.append('Password-recovery SQL migration is missing')
else:
    sql = migration.read_text(encoding='utf-8')
    if not sql.lstrip().startswith('BEGIN;') or not sql.rstrip().endswith('COMMIT;'):
        failures.append('Password-recovery SQL migration lacks transaction boundaries')
    if sql.count('$$') % 2:
        failures.append('Password-recovery SQL migration has unbalanced $$ delimiters')
    for required in ['auth_user_directory', 'password_reset_requests', 'password_reset_audit']:
        if required not in sql:
            failures.append(f'Password-recovery SQL migration is missing {required}')

if failures:
    print(f'Campus Desk backend verification failed ({len(failures)} issue(s)):')
    for failure in failures:
        print(f'- {failure}')
    raise SystemExit(1)

print('Campus Desk Python backend source verification passed.')
