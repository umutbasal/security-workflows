export const meta = {
  name: "vuln-discovery",
  description:
    "Multi-stage web application vulnerability discovery harness with OWASP-aligned attack classes, gapfill, and feedback loops",
  phases: [
    { title: "Recon", detail: "map architecture, trust boundaries, and generate hunt tasks" },
    { title: "Hunt", detail: "parallel vulnerability search across attack classes" },
    { title: "Validate", detail: "adversarial review to eliminate false positives" },
    { title: "Gapfill", detail: "re-queue under-covered areas" },
    { title: "Dedupe", detail: "collapse same root-cause findings" },
    { title: "Feedback", detail: "generate new hunt tasks from confirmed findings" },
    { title: "Report", detail: "structured vulnerability report with exploit PoCs" },
  ],
};

const dir = args?.dir || ".";
const maxRounds = args?.maxRounds ?? 3;
const concurrency = args?.concurrency ?? 10;

// ─── Web Application Attack Classes ─────────────────────────────────────────
// Organized by OWASP Top 10 + additional web-specific classes
const ATTACK_CLASSES = {
  // A03:2021 – Injection
  injection: [
    {
      id: "sqli",
      name: "SQL Injection",
      description: "Unsanitized user input concatenated into SQL queries (string interpolation, dynamic query building)",
      indicators: ["string template literals with SQL", "concatenation in .prepare()/.exec()/.query()", "no parameterized queries"],
      severity_if_found: "critical",
    },
    {
      id: "cmdi",
      name: "Command Injection",
      description: "User input passed to shell execution functions (exec, execSync, spawn) without sanitization",
      indicators: ["execSync/exec/spawn with user input", "template strings in shell commands", "no input validation before shell"],
      severity_if_found: "critical",
    },
    {
      id: "ssti",
      name: "Server-Side Template Injection",
      description: "User input evaluated in template engines or eval()-like constructs",
      indicators: ["eval()", "Function()", "template literal interpolation with user data", "custom template engines"],
      severity_if_found: "critical",
    },
    {
      id: "nosqli",
      name: "NoSQL Injection",
      description: "Object/operator injection in NoSQL queries (MongoDB $gt, $ne, etc.)",
      indicators: ["JSON body passed directly to query", "no type checking on query params"],
      severity_if_found: "high",
    },
    {
      id: "ldap-injection",
      name: "LDAP Injection",
      description: "User input in LDAP filter strings without escaping",
      indicators: ["ldap search with string concat", "unescaped special chars in DN"],
      severity_if_found: "high",
    },
  ],

  // A01:2021 – Broken Access Control
  access_control: [
    {
      id: "idor",
      name: "Insecure Direct Object Reference",
      description: "Accessing resources by manipulating identifiers without ownership verification",
      indicators: ["user_id from request body/params", "no ownership check after fetch", "trusting client-sent IDs"],
      severity_if_found: "high",
    },
    {
      id: "privilege-escalation",
      name: "Privilege Escalation",
      description: "Accessing admin/elevated functionality through header manipulation, role tampering, or missing auth checks",
      indicators: ["role check via headers only", "admin endpoints without session validation", "trusting x-* headers"],
      severity_if_found: "critical",
    },
    {
      id: "forced-browsing",
      name: "Forced Browsing / Missing Function-Level Access Control",
      description: "Accessing restricted endpoints/resources by directly requesting URLs without authorization",
      indicators: ["no auth middleware on sensitive routes", "inconsistent auth checks", "admin paths without guards"],
      severity_if_found: "high",
    },
    {
      id: "mass-assignment",
      name: "Mass Assignment / Parameter Pollution",
      description: "Updating restricted fields by sending extra parameters the server blindly accepts",
      indicators: ["Object.assign/spread with user input", "dynamic SET clauses from body", "no field allowlist"],
      severity_if_found: "high",
    },
    {
      id: "open-redirect",
      name: "Open Redirect",
      description: "Redirecting users to attacker-controlled URLs via unvalidated redirect parameters",
      indicators: ["Location header from user input", "redirect URL from query param", "no allowlist check"],
      severity_if_found: "medium",
    },
  ],

  // A02:2021 – Cryptographic Failures
  crypto_failures: [
    {
      id: "plaintext-secrets",
      name: "Plaintext Secrets / Credentials",
      description: "Passwords stored in plaintext, API keys hardcoded, secrets in source code or DB without encryption",
      indicators: ["password columns without hashing", "hardcoded API keys", "secrets in seed data"],
      severity_if_found: "critical",
    },
    {
      id: "weak-tokens",
      name: "Weak Token Generation",
      description: "Predictable session tokens, reset tokens, or API keys using Math.random() or sequential values",
      indicators: ["Math.random()", "Date.now() as token", "sequential IDs as secrets", "no crypto.randomBytes"],
      severity_if_found: "high",
    },
    {
      id: "sensitive-data-exposure",
      name: "Sensitive Data in API Responses",
      description: "Returning passwords, tokens, internal IDs, or PII in API responses that shouldn't contain them",
      indicators: ["SELECT * returning password fields", "reset token in response body", "env vars in responses"],
      severity_if_found: "high",
    },
  ],

  // A07:2021 – Cross-Site Scripting (XSS)
  xss: [
    {
      id: "reflected-xss",
      name: "Reflected XSS",
      description: "User input reflected in HTML responses without encoding/escaping",
      indicators: ["query params in HTML response", "Content-Type: text/html with user data", "no HTML entity encoding"],
      severity_if_found: "high",
    },
    {
      id: "stored-xss",
      name: "Stored XSS",
      description: "User-submitted content (posts, comments, bios) stored and rendered without sanitization",
      indicators: ["user content in DB rendered as HTML", "innerHTML with stored data", "no CSP headers"],
      severity_if_found: "high",
    },
    {
      id: "dom-xss",
      name: "DOM-based XSS",
      description: "Client-side JavaScript using untrusted data in dangerous sinks (innerHTML, eval, document.write)",
      indicators: ["innerHTML assignment", "document.write with user data", "eval() in client code"],
      severity_if_found: "medium",
    },
  ],

  // A10:2021 – Server-Side Request Forgery (SSRF)
  ssrf: [
    {
      id: "ssrf",
      name: "Server-Side Request Forgery",
      description: "Server fetches attacker-specified URLs, allowing access to internal services, cloud metadata, or localhost",
      indicators: ["fetch/axios/http.get with user URL", "no URL validation", "no allowlist/blocklist for hosts"],
      severity_if_found: "high",
    },
    {
      id: "ssrf-cloud-metadata",
      name: "SSRF to Cloud Metadata",
      description: "SSRF targeting cloud provider metadata endpoints (169.254.169.254, instance metadata)",
      indicators: ["same as SSRF but targeting cloud metadata specifically"],
      severity_if_found: "critical",
    },
  ],

  // A08:2021 – Software and Data Integrity Failures
  integrity: [
    {
      id: "prototype-pollution",
      name: "Prototype Pollution",
      description: "Recursive object merge/deep copy allowing __proto__ or constructor.prototype injection",
      indicators: ["recursive merge without key filtering", "lodash.merge with user input", "deep clone from untrusted data"],
      severity_if_found: "high",
    },
    {
      id: "deserialization",
      name: "Insecure Deserialization",
      description: "Deserializing untrusted data that can trigger code execution or object manipulation",
      indicators: ["JSON.parse of base64 user input", "eval of serialized data", "yaml.load with untrusted input"],
      severity_if_found: "high",
    },
  ],

  // A04:2021 – Insecure Design
  insecure_design: [
    {
      id: "race-condition",
      name: "Race Conditions / TOCTOU",
      description: "Time-of-check to time-of-use issues in concurrent operations (double-spend, duplicate actions)",
      indicators: ["check-then-act without locks", "non-atomic read-modify-write", "parallel request exploitation"],
      severity_if_found: "medium",
    },
    {
      id: "business-logic",
      name: "Business Logic Flaws",
      description: "Bypassing intended workflow (skipping steps, reusing tokens, negative values, boundary abuse)",
      indicators: ["multi-step processes", "token reuse after consumption", "missing state machine checks"],
      severity_if_found: "medium",
    },
  ],

  // A05:2021 – Security Misconfiguration
  misconfig: [
    {
      id: "info-disclosure",
      name: "Information Disclosure",
      description: "Leaking internal state: stack traces, env vars, DB schema, debug endpoints, verbose errors",
      indicators: ["process.env in response", "error.stack in response", "debug routes without auth", "schema exposure"],
      severity_if_found: "medium",
    },
    {
      id: "missing-security-headers",
      name: "Missing Security Headers",
      description: "Absent or misconfigured security headers (CSP, X-Frame-Options, HSTS, X-Content-Type-Options)",
      indicators: ["no Content-Security-Policy", "no X-Frame-Options", "no Strict-Transport-Security"],
      severity_if_found: "low",
    },
    {
      id: "cors-misconfiguration",
      name: "CORS Misconfiguration",
      description: "Overly permissive CORS allowing credential theft from any origin",
      indicators: ["Access-Control-Allow-Origin: *", "reflecting Origin header", "credentials: true with wildcard"],
      severity_if_found: "medium",
    },
  ],

  // A07:2021 – Identification and Authentication Failures
  auth_failures: [
    {
      id: "broken-auth",
      name: "Broken Authentication",
      description: "Weak login mechanisms, token leakage, session fixation, no rate limiting, credential stuffing",
      indicators: ["no brute-force protection", "tokens in URL/response", "session tokens not rotated"],
      severity_if_found: "high",
    },
    {
      id: "auth-bypass",
      name: "Authentication Bypass",
      description: "Circumventing authentication entirely via alternative paths, parameter manipulation, or logic flaws",
      indicators: ["SQL injection in login", "type juggling in comparison", "fallback paths without auth"],
      severity_if_found: "critical",
    },
  ],

  // File/Path related
  file_access: [
    {
      id: "path-traversal",
      name: "Path Traversal / LFI",
      description: "Reading arbitrary files via ../ sequences or absolute paths in file access parameters",
      indicators: ["join/resolve with user input", "no path sanitization", "readFileSync with user-controlled name"],
      severity_if_found: "high",
    },
    {
      id: "file-upload",
      name: "Unrestricted File Upload",
      description: "Uploading malicious files (shells, polyglots) without type/size/content validation",
      indicators: ["file write without extension check", "no MIME validation", "upload to web-accessible dir"],
      severity_if_found: "high",
    },
  ],
};

// ─── Phase 1: Recon ──────────────────────────────────────────────────────────
phase("Recon");
log("Mapping architecture and generating initial hunt tasks...");

const attackClassSummary = Object.entries(ATTACK_CLASSES)
  .map(
    ([category, classes]) =>
      `### ${category}\n${classes.map((c) => `- **${c.name}** (${c.id}): ${c.description}\n  Indicators: ${c.indicators.join(", ")}`).join("\n")}`
  )
  .join("\n\n");

const recon = await agent(
  `Analyze the web application project in "${dir}". This is a Bun/TypeScript web application.

Produce an architecture map covering:
- HTTP routes and their methods (GET/POST/PUT/DELETE)
- Trust boundaries (user input → processing → output/storage)
- Authentication mechanisms and session management
- Database interactions (queries, ORM, raw SQL)
- External calls (fetch, exec, file system, DNS)
- Client-side JavaScript (DOM manipulation, data flow)
- Input parsing (JSON, form data, query params, headers, cookies)
- Output rendering (HTML, JSON, redirects)

Then generate a comprehensive list of hunt tasks. Each task pairs ONE specific attack class with ONE specific endpoint or code location.

Available attack classes to consider:
${attackClassSummary}

IMPORTANT: Generate tasks based on what the code ACTUALLY does. For each endpoint/function:
1. Identify what user inputs it accepts
2. Identify what dangerous operations it performs with those inputs
3. Match to the most relevant attack class(es)

Be thorough — generate tasks for EVERY endpoint and EVERY plausible attack vector. This app is intentionally vulnerable so expect many findings.`,
  {
    label: "recon",
    schema: {
      type: "object",
      properties: {
        architecture: {
          type: "object",
          properties: {
            routes: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  method: { type: "string" },
                  path: { type: "string" },
                  inputs: { type: "array", items: { type: "string" } },
                  operations: { type: "array", items: { type: "string" } },
                },
              },
            },
            trust_boundaries: { type: "array", items: { type: "string" } },
            auth_mechanisms: { type: "array", items: { type: "string" } },
            data_flows: { type: "array", items: { type: "string" } },
            external_interfaces: { type: "array", items: { type: "string" } },
          },
        },
        tasks: {
          type: "array",
          items: {
            type: "object",
            properties: {
              attack_class: { type: "string" },
              attack_class_id: { type: "string" },
              scope: { type: "string" },
              endpoint: { type: "string" },
              hypothesis: { type: "string" },
              user_input_vector: { type: "string" },
              dangerous_operation: { type: "string" },
            },
          },
        },
      },
    },
  }
);

log(`Recon complete: ${recon.tasks.length} hunt tasks generated across ${new Set(recon.tasks.map((t) => t.attack_class_id)).size} attack classes`);

// ─── State ───────────────────────────────────────────────────────────────────
let allFindings = [];
let taskQueue = [...recon.tasks];
let coveredAreas = new Set();
let round = 0;

// ─── Main Loop: Hunt → Validate → Gapfill → Feedback ────────────────────────
while (taskQueue.length > 0 && round < maxRounds) {
  round++;
  log(`── Round ${round}/${maxRounds} ── ${taskQueue.length} tasks in queue`);

  const currentBatch = taskQueue.splice(0, concurrency);

  // ─── Phase 2: Hunt (parallel) ────────────────────────────────────────────
  phase("Hunt");
  log(`Hunting: ${currentBatch.length} concurrent tasks...`);

  const huntResults = await parallel(
    currentBatch.map((task) => () =>
      agent(
        `You are an expert web application security researcher performing a targeted vulnerability assessment.

## Your Assignment
- **Attack class**: ${task.attack_class} (${task.attack_class_id})
- **Target scope**: ${task.scope}
- **Endpoint**: ${task.endpoint || "N/A"}
- **Hypothesis**: ${task.hypothesis}
- **Input vector**: ${task.user_input_vector || "Unknown"}
- **Dangerous operation**: ${task.dangerous_operation || "Unknown"}

## Instructions
1. Read the code at the specified scope thoroughly
2. Trace the data flow from user input to the dangerous operation
3. Identify if/where sanitization or validation occurs (or is missing)
4. Determine exploitability — can an attacker actually reach and trigger this?
5. Construct a concrete proof-of-concept (HTTP request, curl command, or payload)
6. Assess real-world impact (data theft, RCE, privilege escalation, etc.)

## For this attack class specifically:
${getAttackClassGuidance(task.attack_class_id)}

## Output Requirements
- Only report REAL vulnerabilities you can prove with a concrete exploit path
- Include the exact malicious input/payload
- Describe the expected server behavior when exploited
- Rate confidence: high (PoC works), medium (likely exploitable), low (theoretical)
- Note which parts of scope you covered vs areas you only skimmed`,
        {
          label: `hunt:${task.attack_class_id}:${(task.endpoint || task.scope).split("/").pop()}`,
          schema: {
            type: "object",
            properties: {
              findings: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    vulnerability: { type: "string" },
                    attack_class: { type: "string" },
                    severity: { enum: ["critical", "high", "medium", "low"] },
                    location: { type: "string" },
                    endpoint: { type: "string" },
                    description: { type: "string" },
                    exploit_path: { type: "string" },
                    poc_payload: { type: "string" },
                    impact: { type: "string" },
                    confidence: { enum: ["high", "medium", "low"] },
                    cwe: { type: "string" },
                  },
                },
              },
              covered: { type: "array", items: { type: "string" } },
              gaps: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    area: { type: "string" },
                    reason: { type: "string" },
                  },
                },
              },
            },
          },
        }
      ).catch((err) => ({ findings: [], covered: [], gaps: [], error: err.message }))
    )
  );

  const roundFindings = huntResults.flatMap((r) => r?.findings ?? []);
  const roundGaps = huntResults.flatMap((r) => r?.gaps ?? []);
  huntResults.forEach((r) => (r?.covered ?? []).forEach((c) => coveredAreas.add(c)));

  log(`Hunt round ${round}: ${roundFindings.length} raw findings, ${roundGaps.length} gaps`);

  // ─── Phase 3: Validate (adversarial) ──────────────────────────────────────
  phase("Validate");
  if (roundFindings.length > 0) {
    log(`Validating ${roundFindings.length} findings with adversarial review...`);

    const validated = await parallel(
      roundFindings.map((finding) => () =>
        agent(
          `You are an adversarial security reviewer specializing in web application security. Your job is to DISPROVE this finding or confirm it's real.

## Finding Under Review
- **Vulnerability**: ${finding.vulnerability}
- **Attack class**: ${finding.attack_class}
- **Location**: ${finding.location}
- **Endpoint**: ${finding.endpoint}
- **Claimed exploit**: ${finding.exploit_path}
- **PoC payload**: ${finding.poc_payload}
- **Impact claim**: ${finding.impact}

## Your Review Checklist
1. **Input reachability**: Is the user input actually attacker-controlled? Or is it from a trusted source?
2. **Sanitization**: Are there input validation, encoding, or sanitization steps the hunter missed?
3. **Framework protections**: Does Bun/the runtime provide built-in protections (e.g., parameterized queries, auto-escaping)?
4. **Code reachability**: Is the vulnerable code path actually reachable in production?
5. **Exploit feasibility**: Would the PoC actually work? Are there HTTP/browser restrictions?
6. **Impact accuracy**: Is the claimed impact realistic or overstated?
7. **Prerequisite checks**: Does exploitation require prior authentication or specific conditions?

Read the actual source code to verify. You CANNOT add new findings — only judge this one.
Be tough but fair. If the exploit path is valid, confirm it.`,
          {
            label: `validate:${finding.attack_class}:${finding.location}`,
            schema: {
              type: "object",
              properties: {
                valid: { type: "boolean" },
                reason: { type: "string" },
                adjusted_severity: { enum: ["critical", "high", "medium", "low", "false_positive"] },
                exploitability_notes: { type: "string" },
                prerequisites: { type: "string" },
              },
            },
          }
        ).catch(() => ({
          valid: true,
          reason: "validation agent failed, keeping finding conservatively",
          adjusted_severity: finding.severity,
        }))
      )
    );

    for (let i = 0; i < roundFindings.length; i++) {
      const v = validated[i];
      if (v?.valid && v?.adjusted_severity !== "false_positive") {
        allFindings.push({
          ...roundFindings[i],
          severity: v.adjusted_severity || roundFindings[i].severity,
          validation_note: v.reason,
          exploitability_notes: v.exploitability_notes,
          prerequisites: v.prerequisites,
        });
      } else {
        log(`  ✗ Rejected: ${roundFindings[i].vulnerability} — ${v?.reason}`);
      }
    }

    log(`After validation: ${allFindings.length} confirmed findings total`);
  }

  // ─── Phase 4: Gapfill ─────────────────────────────────────────────────────
  phase("Gapfill");
  if (roundGaps.length > 0 && round < maxRounds) {
    log(`Gapfill: analyzing ${roundGaps.length} under-covered areas...`);

    const gapTasks = await agent(
      `You are a security test planner for a web application. Given these areas that were not thoroughly covered:
${JSON.stringify(roundGaps, null, 2)}

Areas already covered:
${JSON.stringify([...coveredAreas], null, 2)}

Available attack classes:
${Object.values(ATTACK_CLASSES)
  .flat()
  .map((c) => `- ${c.id}: ${c.name} — ${c.description}`)
  .join("\n")}

Generate new hunt tasks for the gaps. Each task should:
1. Pair a specific attack class with a specific endpoint/file/function
2. Only target areas NOT already in the covered list
3. Prioritize areas near trust boundaries or handling user input
4. Include a clear hypothesis of what might be vulnerable and why`,
      {
        label: `gapfill:round-${round}`,
        schema: {
          type: "array",
          items: {
            type: "object",
            properties: {
              attack_class: { type: "string" },
              attack_class_id: { type: "string" },
              scope: { type: "string" },
              endpoint: { type: "string" },
              hypothesis: { type: "string" },
              user_input_vector: { type: "string" },
              dangerous_operation: { type: "string" },
            },
          },
        },
      }
    );

    if (gapTasks && gapTasks.length > 0) {
      taskQueue.push(...gapTasks);
      log(`Gapfill added ${gapTasks.length} new tasks to queue`);
    }
  }

  // ─── Phase 5: Feedback ─────────────────────────────────────────────────────
  phase("Feedback");
  if (allFindings.length > 0 && round < maxRounds) {
    const criticalFindings = allFindings.filter((f) => f.severity === "critical" || f.severity === "high");

    if (criticalFindings.length > 0) {
      log(`Feedback: ${criticalFindings.length} high/critical findings — checking for related vulnerability patterns...`);

      const feedbackTasks = await agent(
        `These validated web application vulnerabilities were confirmed:
${JSON.stringify(criticalFindings, null, 2)}

For each finding, consider:
1. **Pattern repetition**: Does this vulnerability pattern (e.g., SQL injection via string interpolation) appear in other endpoints?
2. **Shared utility impact**: If a utility function is vulnerable, are all its callers also affected?
3. **Chaining opportunities**: Can this finding be combined with another to escalate impact? (e.g., IDOR + info disclosure = account takeover)
4. **Same-class variants**: Are there other injection points for the same attack class?
5. **Defense bypass**: Now that we know the app lacks certain protections, where else might this apply?

Generate NEW hunt tasks targeting related areas that likely share the same vulnerability pattern.
Already covered areas (do NOT regenerate): ${JSON.stringify([...coveredAreas])}

Focus on:
- Other endpoints using the same dangerous patterns
- Chained exploits combining multiple findings
- Variants the original hunter might have missed`,
        {
          label: `feedback:round-${round}`,
          schema: {
            type: "array",
            items: {
              type: "object",
              properties: {
                attack_class: { type: "string" },
                attack_class_id: { type: "string" },
                scope: { type: "string" },
                endpoint: { type: "string" },
                hypothesis: { type: "string" },
                derived_from: { type: "string" },
                chain_with: { type: "string" },
              },
            },
          },
        }
      );

      if (feedbackTasks && feedbackTasks.length > 0) {
        taskQueue.push(...feedbackTasks);
        log(`Feedback added ${feedbackTasks.length} new tasks from existing findings`);
      }
    }
  }
}

// ─── Phase 6: Dedupe ───────────────────────────────────────────────────────
phase("Dedupe");
log(`Deduplicating ${allFindings.length} findings by root cause...`);

const deduped = await agent(
  `Deduplicate these web application vulnerability findings. Group by root cause — findings that share the same underlying code flaw should collapse into a single record.

For example:
- Multiple SQL injection findings on different endpoints using the same pattern → one finding with multiple affected endpoints
- Same missing auth check on different admin routes → one finding

Keep the highest severity, merge exploit paths, and list all affected locations.

Findings:
${JSON.stringify(allFindings, null, 2)}

Also assign CWE IDs where applicable.`,
  {
    label: "dedupe",
    schema: {
      type: "array",
      items: {
        type: "object",
        properties: {
          vulnerability: { type: "string" },
          attack_class: { type: "string" },
          severity: { enum: ["critical", "high", "medium", "low"] },
          locations: { type: "array", items: { type: "string" } },
          endpoints: { type: "array", items: { type: "string" } },
          description: { type: "string" },
          root_cause: { type: "string" },
          exploit_path: { type: "string" },
          poc_payload: { type: "string" },
          impact: { type: "string" },
          cwe: { type: "string" },
          remediation: { type: "string" },
        },
      },
    },
  }
);

// ─── Phase 7: Report ─────────────────────────────────────────────────────────
phase("Report");
const findings = deduped ?? [];
log(`Generating report for ${findings.length} unique vulnerabilities...`);

const severityCounts = {
  critical: findings.filter((f) => f.severity === "critical").length,
  high: findings.filter((f) => f.severity === "high").length,
  medium: findings.filter((f) => f.severity === "medium").length,
  low: findings.filter((f) => f.severity === "low").length,
};

const attackClassCoverage = {};
for (const f of findings) {
  attackClassCoverage[f.attack_class] = (attackClassCoverage[f.attack_class] || 0) + 1;
}

await agent(
  `Write a comprehensive security assessment report to "vuln-discovery-report.md" with this data:

# 🔒 Web Application Security Assessment — tweety

## Executive Summary
- **Assessment rounds**: ${round}
- **Code areas covered**: ${coveredAreas.size}
- **Raw findings (pre-dedup)**: ${allFindings.length}
- **Unique vulnerabilities**: ${findings.length}
- **Critical**: ${severityCounts.critical} | **High**: ${severityCounts.high} | **Medium**: ${severityCounts.medium} | **Low**: ${severityCounts.low}

## Risk Rating
${severityCounts.critical > 0 ? "🔴 **CRITICAL** — Immediate remediation required. Application has exploitable RCE/injection vulnerabilities." : severityCounts.high > 0 ? "🟠 **HIGH** — Significant vulnerabilities requiring prompt attention." : "🟡 **MEDIUM** — Moderate issues found."}

## Architecture Overview
${JSON.stringify(recon.architecture, null, 2)}

## Attack Surface Coverage
Attack classes tested: ${Object.keys(attackClassCoverage).join(", ")}
${JSON.stringify(attackClassCoverage, null, 2)}

## Findings by Severity
${JSON.stringify(findings, null, 2)}

## Format Requirements
For each finding, include:
1. **Severity badge** (🔴 Critical / 🟠 High / 🟡 Medium / 🟢 Low)
2. **CWE ID** and attack class
3. **Vulnerability title** and affected endpoints
4. **Root cause** — why this vulnerability exists
5. **Exploit path** — step-by-step exploitation
6. **Proof of Concept** — exact curl command or HTTP request
7. **Impact** — what an attacker gains
8. **Remediation** — specific code fix recommendation

## Additional Sections to Include
- **Attack Chain Analysis**: How findings can be combined for maximum impact
- **OWASP Top 10 Mapping**: Which OWASP categories are affected
- **Prioritized Remediation Roadmap**: What to fix first and why
- **Security Architecture Recommendations**: Systemic improvements

Make it actionable for developers. Include code snippets showing the vulnerable pattern AND the fixed version.`,
  { label: "write-report" }
);

return {
  summary: {
    rounds: round,
    areas_covered: coveredAreas.size,
    raw_findings: allFindings.length,
    unique_vulnerabilities: findings.length,
    attack_classes_tested: Object.keys(attackClassCoverage).length,
  },
  by_severity: severityCounts,
  by_attack_class: attackClassCoverage,
  findings,
};

// ─── Helper: Attack Class Guidance ───────────────────────────────────────────
function getAttackClassGuidance(classId) {
  const guidance = {
    sqli: `Look for string interpolation/concatenation in SQL queries. Check if user input flows directly into:
- Template literals: \`SELECT * FROM x WHERE y = '\${input}'\`
- String concat: "SELECT * FROM x WHERE y = '" + input + "'"
- Dynamic column/table names from user input
Test payloads: ' OR '1'='1, ' UNION SELECT, '; DROP TABLE, ' AND 1=1--`,

    cmdi: `Look for user input reaching shell execution functions:
- execSync(), exec(), spawn(), spawnSync()
- Input in command arguments without escaping
Test payloads: ; id, | cat /etc/passwd, \$(whoami), \`whoami\`, && curl attacker.com`,

    ssti: `Look for user input evaluated as code:
- eval() with user-controlled strings
- Function() constructor with user input
- Template engines with user-controlled templates
Test payloads: {{7*7}}, {{constructor.constructor('return process')()}}, \${require('child_process').execSync('id')}`,

    idor: `Look for resource access without ownership verification:
- Fetching records by user-supplied ID
- No check that current user owns the resource
- user_id from request body instead of session
Test: Change user_id parameter to access other users' data`,

    "privilege-escalation": `Look for admin/elevated access without proper authentication:
- Header-based auth checks (X-Admin, X-Role)
- Role checks that can be bypassed
- Admin endpoints without session validation
Test: Add X-Admin-Access: true header, change role field`,

    "mass-assignment": `Look for:
- Direct spread/assignment of request body to DB updates
- No allowlist of updatable fields
- User can set role, is_admin, password via extra params
Test: Add "role": "admin" to profile update request`,

    "reflected-xss": `Look for user input reflected in HTML without encoding:
- Query params in Content-Type: text/html responses
- Error messages containing user input
- Search results displaying the query
Test payloads: <script>alert(1)</script>, <img onerror=alert(1) src=x>, javascript:alert(1)`,

    "stored-xss": `Look for user-submitted content rendered as HTML:
- Posts, comments, bios stored and displayed
- No HTML sanitization on output
- Content-Type: text/html for user content
Test: Store <script>alert(document.cookie)</script> in bio/post`,

    ssrf: `Look for server-side URL fetching:
- fetch(), axios, http.get() with user-supplied URL
- No protocol/host validation
- Can target internal services (localhost, 169.254.169.254)
Test: url=http://localhost:3000/api/admin/system, url=http://169.254.169.254/latest/meta-data/`,

    "prototype-pollution": `Look for recursive object merging:
- Custom deep merge functions
- lodash.merge, Object.assign with nested objects
- No filtering of __proto__, constructor, prototype keys
Test: {"__proto__": {"isAdmin": true}}, {"constructor": {"prototype": {"isAdmin": true}}}`,

    "path-traversal": `Look for file operations with user-controlled paths:
- join(), resolve() with user input
- No sanitization of ../ sequences
- readFileSync, readFile with user-controlled path
Test: ../../etc/passwd, ....//....//etc/passwd, ..%2F..%2Fetc%2Fpasswd`,

    "weak-tokens": `Look for token generation using:
- Math.random() (predictable with state)
- Date.now() (guessable timestamp)
- Sequential counters
Should use: crypto.randomBytes(), crypto.randomUUID()`,

    "plaintext-secrets": `Look for:
- Passwords stored without hashing (bcrypt/argon2)
- API keys/credentials hardcoded in source
- Secrets in database seed data
- .env files committed to git`,

    "sensitive-data-exposure": `Look for API responses that include:
- Password fields (SELECT * without column filtering)
- Internal tokens (reset_token in response)
- Environment variables
- Full database schemas`,

    "open-redirect": `Look for redirects using user-supplied URLs:
- Location header from query parameter
- No validation against allowlist
- Can redirect to attacker.com for phishing
Test: ?url=https://evil.com, ?url=//evil.com, ?url=/\\evil.com`,

    "broken-auth": `Look for:
- Reset tokens returned in HTTP response (should be email-only)
- No rate limiting on login attempts
- Session tokens not invalidated on password change
- Predictable token format`,

    "auth-bypass": `Look for:
- SQL injection in login allowing auth bypass
- Type coercion issues in password comparison
- Alternative login paths without full validation
Test: Login with username: admin'-- password: anything`,

    "info-disclosure": `Look for endpoints that expose:
- process.env (API keys, secrets, DB credentials)
- Database schema (table names, column names)
- Stack traces with file paths
- Debug/system endpoints without auth`,

    deserialization: `Look for:
- Base64 decode → JSON.parse → use in sensitive operations
- Object with executable callbacks
- Data from untrusted sources used to construct objects
Test: Craft base64 payload with __proto__ or constructor manipulation`,

    "race-condition": `Look for non-atomic operations:
- Read balance → check → deduct (double spend)
- Token generation → store (race to use before stored)
- Check existence → create (duplicate registration)`,

    "business-logic": `Look for:
- Password reset tokens that don't expire
- No validation that reset token matches requesting user
- Multi-step operations with no state verification`,

    "cors-misconfiguration": `Look for:
- No CORS headers (defaults may be permissive)
- Reflecting Origin without validation
- credentials: true with wildcard`,

    "missing-security-headers": `Check for absence of:
- Content-Security-Policy
- X-Frame-Options
- X-Content-Type-Options
- Strict-Transport-Security
- X-XSS-Protection (legacy but still useful)`,

    "dom-xss": `Look for client-side JavaScript that:
- Sets innerHTML with data from URL/storage
- Uses document.write()
- Passes untrusted data to eval()
- Reads from location.hash or URL params unsafely`,

    "file-upload": `Look for:
- File upload endpoints without extension validation
- No MIME type checking
- Files stored in web-accessible directories
- No size limits`,

    "nosqli": `Look for NoSQL query construction with:
- Direct use of parsed JSON in queries
- No type validation on query parameters
- Operator injection ($gt, $ne, $regex)`,

    "ldap-injection": `Look for LDAP queries with:
- String interpolation in search filters
- Unescaped special characters (*, (, ), \\, NUL)
- User input in Distinguished Names`,

    "ssrf-cloud-metadata": `Same as SSRF but specifically test:
- http://169.254.169.254/latest/meta-data/
- http://metadata.google.internal/
- http://100.100.100.200/latest/meta-data/ (Alibaba)`,
  };

  return guidance[classId] || `Apply standard testing methodology for ${classId}. Look for missing input validation, missing output encoding, and missing access controls.`;
}
