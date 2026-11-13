export const PACKAGE_NAME = 'dsh-codex-security';
export const PLUGIN_NAME = 'codex-security';
export const VERSION = '0.1.0';
export const ROUTE_PREFIX = '/plugins/codex-security';
export const PRODUCER = { name: 'dsh-codex-security', version: VERSION };
export const DEFAULT_EXCLUDES = ['.git/**', 'node_modules/**', 'dist/**', 'build/**', 'out/**', 'coverage/**', '.next/**', '.nuxt/**', 'vendor/**', 'target/**', '.venv/**', '__pycache__/**'];
export const SKILL_NAMES = ['security-scan', 'security-diff-scan', 'deep-security-scan', 'fix-finding', 'verify-fix', 'triage-finding', 'threat-model', 'track-findings', 'resolve-dependency-alert', 'vulnerability-writeup'];
export const TOOL_NAMES = [
    'codex_security_inspect_setup', 'codex_security_inspect_target',
    'codex_security_start_standard_scan', 'codex_security_start_prompt_only_scan', 'codex_security_start_deep_scan',
    'codex_security_get_scan_context', 'codex_security_update_scan_context', 'codex_security_update_scan_progress',
    'codex_security_record_scan_draft', 'codex_security_record_discovery_candidates', 'codex_security_list_candidates',
    'codex_security_record_candidate_validations', 'codex_security_record_candidate_attack_paths',
    'codex_security_save_artifact', 'codex_security_read_artifact',
    'codex_security_complete_scan', 'codex_security_fail_scan', 'codex_security_cancel_scan',
    'codex_security_list_scans', 'codex_security_get_scan', 'codex_security_list_findings',
    'codex_security_set_finding_triage', 'codex_security_set_finding_remediation', 'codex_security_export_findings',
    'codex_security_prepare_review_items', 'codex_security_list_review_items', 'codex_security_compare_scans',
];
