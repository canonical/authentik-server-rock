## 🚀 Upstream Authentik Upgrade Specification: v{{ CURRENT_VER }} → v{{ NEW_VER }}

> **For Engineers & AI Coding Agents:** This issue contains a complete specification to update the charm for Authentik `v{{ NEW_VER }}`.
> You can feed this issue directly to an agent (e.g. Antigravity) with:
> `Read this issue and implement all required charm changes, then run unit and integration tests to confirm.`

---

{{ BANNERS }}### 1. Upstream Summary & Impact Assessment
- **Upstream Version**: [{{ NEW_VER }}]({{ UPSTREAM_RELEASE_URL }}) (Previous: `{{ CURRENT_VER }}`)
{{ ROCK_PR_LINE }}
- **Breaking Changes**: {{ BREAKING_BADGE }}
- **Severity**: `{{ SEVERITY }}`
- **Affected Components**: `{{ AFFECTED_COMPONENTS }}`

**Summary of Upstream Changes:**
{{ BREAKING_CHANGES_SUMMARY }}

---

### 2. Action Items for the Charm
{{ CHARM_IMPACT_SUMMARY }}

{{ CHARM_ACTION_ITEMS }}

---

### 3. Testing & Verification Matrix (MUST BE CONFIRMED)

#### A. Automated Test Suite
Run local checks:
```bash
{{ AUTOMATED_TESTS }}
```

#### B. In-Cluster Service Health Checks
Once deployed or upgraded on a test model:
```bash
{{ IN_CLUSTER_CHECKS }}
```

#### C. Specific Regression Probes
{{ REGRESSION_PROBES }}

---

### 4. Definition of Done
{{ DEFINITION_OF_DONE }}
