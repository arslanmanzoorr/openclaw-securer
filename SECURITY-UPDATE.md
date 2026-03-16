# Security Update - March 2026

## Overview

This update addresses two critical security vulnerabilities in OpenClaw:

1. **Plaintext credential storage** - API keys, auth tokens, and secrets were stored in plaintext JSON files on disk
2. **ClawHub supply-chain compromise** - The ClawHub community skill registry was found to host 800+ malicious skills (ClawHavoc campaign)

---

## 1. Credential Encryption at Rest

### Problem

All authentication profiles (API keys, OAuth tokens, session secrets) were stored as plaintext JSON in the user config directory. Any process or user with filesystem read access could exfiltrate credentials.

### Solution

Introduced AES-256-GCM encryption with HKDF-derived keys tied to device identity.

### Files Changed

| File | Change |
|------|--------|
| `src/infra/credential-encryption.ts` | **New file.** Provides `encryptValue()` / `decryptValue()` using AES-256-GCM. Key material is derived via HKDF-SHA256 from machine hostname + username + a static application salt. Includes transparent migration support for existing plaintext credentials. |
| `src/infra/json-file.ts` | Added `loadEncryptedJsonFile()` and `saveEncryptedJsonFile()` functions. On read, attempts decryption first; if decryption fails (e.g., legacy plaintext data), falls back to raw JSON parse and re-encrypts on next write. |
| `src/agents/auth-profiles/store.ts` | All auth profile load/save calls now route through encrypted JSON helpers instead of plaintext `loadJsonFile`/`saveJsonFile`. |

### How It Works

- **Encryption**: AES-256-GCM (authenticated encryption with associated data)
- **Key Derivation**: HKDF-SHA256 with device-bound input key material (`hostname + username + app salt`)
- **Storage Format**: `{ iv, tag, ciphertext }` (base64-encoded fields)
- **Migration**: First read of a plaintext file succeeds via fallback and the file is re-encrypted on the next write cycle

### Limitations

- Keys are derived from device identity, not a user-provided passphrase. This protects against offline exfiltration but not against a local attacker running as the same user.
- Future improvement: integrate with OS keychain (Windows DPAPI / macOS Keychain / Linux Secret Service).

---

## 2. ClawHub Registry Disabled

### Problem

ClawHub (clawhub.com) is the community marketplace for OpenClaw skills. The **ClawHavoc campaign** compromised the registry with 800+ malicious skills that could:

- Exfiltrate environment variables and credentials
- Execute arbitrary code during skill installation
- Inject malicious prompts into agent system prompts
- Establish persistence via post-install hooks

The existing security measures (pattern-based moderation, GitHub account age checks) were insufficient to prevent the attack.

### Solution

ClawHub integration has been **completely disabled** across all layers of the application until the registry implements adequate security controls (code signing, sandboxed execution, verified publishers).

### Files Changed

| File | Change |
|------|--------|
| `src/agents/skills-install-download.ts` | `installDownloadSpec()` now returns immediately with a security error. All remote skill archive downloads are blocked. Original implementation is preserved but unreachable. |
| `src/agents/skills-install.ts` | Added `BLOCKED_SKILL_NAMES` set (`clawhub`, `claw-hub`, `clawhub-cli`). The `installSkill()` function rejects these by name before any further processing. |
| `skills/clawhub/SKILL.md` | Bundled ClawHub skill marked as `enabled: false`. Description updated to security warning. Install options array emptied. |
| `ui/src/ui/views/skills.ts` | "Browse Skills Store" link replaced with a disabled/greyed-out element with tooltip explaining the security concern. |
| `src/agents/system-prompt.ts` | Replaced `"Find new skills: https://clawhub.com"` with a security warning instructing the agent to never suggest ClawHub installations. |
| `src/cli/skills-cli.format.ts` | The `appendClawHubHint()` function now displays a security notice instead of the `npx clawhub` tip. |

### Defense Layers

The ClawHub cutoff is enforced at **six independent layers** to prevent bypass:

```
Layer 1: Download blocked     - installDownloadSpec() rejects all remote fetches
Layer 2: Install blocked      - installSkill() rejects ClawHub-named skills
Layer 3: Skill disabled       - Bundled SKILL.md has enabled: false
Layer 4: UI removed           - Web UI link greyed out with explanation
Layer 5: Agent instructed     - System prompt warns against suggesting ClawHub
Layer 6: CLI updated          - User-facing hints replaced with security notice
```

### What Still Works

- **Local/bundled skills** continue to function normally
- **Manually placed skills** in `./skills` or `~/.openclaw/skills` directories are unaffected
- **Skill configuration** (`allowBundled`, `extraDirs`) works as before

### Re-enabling ClawHub (Future)

When ClawHub implements adequate security controls, re-enable by:

1. Remove the early return in `installDownloadSpec()` (restore original implementation)
2. Remove the `BLOCKED_SKILL_NAMES` check in `installSkill()`
3. Set `enabled: true` in `skills/clawhub/SKILL.md` and restore install options
4. Restore the link in `ui/src/ui/views/skills.ts`
5. Update the system prompt in `src/agents/system-prompt.ts`
6. Update the CLI hint in `src/cli/skills-cli.format.ts`

Recommended security controls before re-enabling:
- Cryptographic skill signing with verified publisher certificates
- Sandboxed skill execution (no raw filesystem/network access)
- Mandatory code review for skills exceeding a complexity threshold
- VirusTotal integration (was listed as "coming soon" in threat model)
- Content-hash pinning in lock files

---

## Testing

After applying this update:

1. Verify credentials are encrypted: check auth profile JSON files for `{ iv, tag, ciphertext }` structure instead of plaintext
2. Verify ClawHub is blocked: run `openclaw skills list` and confirm the security notice appears
3. Verify skill install is blocked: attempt `clawhub install <any-skill>` and confirm rejection
4. Verify existing local skills still load normally
