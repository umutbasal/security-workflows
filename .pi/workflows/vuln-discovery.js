export const meta = {
  name: "vuln-discovery",
  description: "Multi-stage vulnerability discovery harness with gapfill and feedback loops (inspired by Cloudflare's Project Glasswing)",
  phases: [
    { title: "Recon", detail: "map architecture and generate hunt tasks" },
    { title: "Hunt", detail: "parallel vulnerability search" },
    { title: "Validate", detail: "adversarial review of findings" },
    { title: "Gapfill", detail: "re-queue under-covered areas" },
    { title: "Dedupe", detail: "collapse same root-cause findings" },
    { title: "Feedback", detail: "generate new hunt tasks from findings" },
    { title: "Report", detail: "structured vulnerability report" },
  ],
};

const dir = args?.dir || ".";
const maxRounds = args?.maxRounds ?? 3;
const concurrency = args?.concurrency ?? 10;

// ─── Phase 1: Recon ──────────────────────────────────────────────────────────
phase("Recon");
log("Mapping architecture and generating initial hunt tasks...");

const recon = await agent(
  `Analyze the project in "${dir}". Produce an architecture map covering:
- Build system and entry points
- Trust boundaries (user input → processing → output)
- External interfaces (HTTP handlers, CLI args, file parsers, DB queries, IPC)
- Authentication/authorization boundaries
- Data flow paths where untrusted input crosses trust boundaries

Then generate a list of hunt tasks. Each task pairs ONE attack class with ONE specific scope (file or function).
Attack classes to consider: command injection, SQL injection, XSS, path traversal, SSRF, auth bypass, deserialization, race conditions, buffer issues, information disclosure.

Only generate tasks where the attack class is plausible for the given scope.`,
  {
    label: "recon",
    schema: {
      type: "object",
      properties: {
        architecture: {
          type: "object",
          properties: {
            entry_points: { type: "array", items: { type: "string" } },
            trust_boundaries: { type: "array", items: { type: "string" } },
            external_interfaces: { type: "array", items: { type: "string" } },
          },
        },
        tasks: {
          type: "array",
          items: {
            type: "object",
            properties: {
              attack_class: { type: "string" },
              scope: { type: "string" },
              hypothesis: { type: "string" },
            },
          },
        },
      },
    },
  }
);

log(`Recon complete: ${recon.tasks.length} hunt tasks generated`);

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
        `You are a security researcher. Your task:
- Attack class: ${task.attack_class}
- Scope: ${task.scope}
- Hypothesis: ${task.hypothesis}

Read the code at the specified scope. Look specifically for ${task.attack_class} vulnerabilities.
Try to construct a proof-of-concept or describe the exact exploit path.
Also note which parts of the scope you examined thoroughly vs areas you only skimmed.`,
        {
          label: `hunt:${task.attack_class}:${task.scope.split("/").pop()}`,
          schema: {
            type: "object",
            properties: {
              findings: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    vulnerability: { type: "string" },
                    severity: { enum: ["critical", "high", "medium", "low"] },
                    location: { type: "string" },
                    description: { type: "string" },
                    exploit_path: { type: "string" },
                    confidence: { enum: ["high", "medium", "low"] },
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
          `You are an adversarial security reviewer. Your job is to DISPROVE this finding.
Read the code and try to show this is a false positive.

Finding: ${finding.vulnerability}
Location: ${finding.location}
Claimed exploit: ${finding.exploit_path}
Description: ${finding.description}

Check:
1. Is the input actually attacker-controlled?
2. Are there sanitization/validation steps the original hunter missed?
3. Does the framework provide built-in protection?
4. Is the vulnerable code actually reachable?

You CANNOT emit new findings. Only judge this one.`,
          {
            label: `validate:${finding.location}`,
            schema: {
              type: "object",
              properties: {
                valid: { type: "boolean" },
                reason: { type: "string" },
                adjusted_severity: { enum: ["critical", "high", "medium", "low", "false_positive"] },
              },
            },
          }
        ).catch(() => ({ valid: true, reason: "validation failed, keeping finding", adjusted_severity: finding.severity }))
      )
    );

    for (let i = 0; i < roundFindings.length; i++) {
      const v = validated[i];
      if (v?.valid && v?.adjusted_severity !== "false_positive") {
        allFindings.push({
          ...roundFindings[i],
          severity: v.adjusted_severity || roundFindings[i].severity,
          validation_note: v.reason,
        });
      }
    }

    log(`After validation: ${allFindings.length} confirmed findings total`);
  }

  // ─── Phase 4: Gapfill ─────────────────────────────────────────────────────
  phase("Gapfill");
  if (roundGaps.length > 0 && round < maxRounds) {
    log(`Gapfill: re-queuing ${roundGaps.length} under-covered areas...`);

    const gapTasks = await agent(
      `Given these areas that were not thoroughly covered in the security review:
${JSON.stringify(roundGaps, null, 2)}

And these areas already covered:
${JSON.stringify([...coveredAreas], null, 2)}

Generate new hunt tasks for the gaps. Each task should pair an attack class with a specific scope.
Only generate tasks for areas NOT already in the covered list.
Prioritize areas near trust boundaries or handling user input.`,
      {
        label: `gapfill:round-${round}`,
        schema: {
          type: "array",
          items: {
            type: "object",
            properties: {
              attack_class: { type: "string" },
              scope: { type: "string" },
              hypothesis: { type: "string" },
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
    const newFindings = allFindings.filter((f) => f.severity === "critical" || f.severity === "high");

    if (newFindings.length > 0) {
      log(`Feedback: checking if ${newFindings.length} high/critical findings imply related vulnerabilities...`);

      const feedbackTasks = await agent(
        `These validated vulnerabilities were found:
${JSON.stringify(newFindings, null, 2)}

For each finding, consider:
1. Does this pattern likely repeat elsewhere in the codebase? (same function called from other locations)
2. Does this finding in a shared utility/library mean consumers are also vulnerable?
3. Does fixing this require checking related code paths?

Generate NEW hunt tasks targeting related areas that may share the same vulnerability pattern.
Do NOT regenerate tasks for already-covered areas: ${JSON.stringify([...coveredAreas])}`,
        {
          label: `feedback:round-${round}`,
          schema: {
            type: "array",
            items: {
              type: "object",
              properties: {
                attack_class: { type: "string" },
                scope: { type: "string" },
                hypothesis: { type: "string" },
                derived_from: { type: "string" },
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
log(`Deduplicating ${allFindings.length} findings...`);

const deduped = await agent(
  `Deduplicate these vulnerability findings. Findings that share the same root cause should collapse into a single record.
Group by root cause, keep the highest severity, and merge descriptions.

Findings:
${JSON.stringify(allFindings, null, 2)}`,
  {
    label: "dedupe",
    schema: {
      type: "array",
      items: {
        type: "object",
        properties: {
          vulnerability: { type: "string" },
          severity: { enum: ["critical", "high", "medium", "low"] },
          locations: { type: "array", items: { type: "string" } },
          description: { type: "string" },
          exploit_path: { type: "string" },
          root_cause: { type: "string" },
        },
      },
    },
  }
);

// ─── Phase 7: Report ─────────────────────────────────────────────────────────
phase("Report");
const findings = deduped ?? [];
log(`Generating report for ${findings.length} unique vulnerabilities...`);

await agent(
  `Write a structured security report to "vuln-discovery-report.md" with this data:

# Vulnerability Discovery Report

## Summary
- Rounds executed: ${round}
- Total areas covered: ${coveredAreas.size}
- Raw findings (pre-dedup): ${allFindings.length}
- Unique vulnerabilities: ${findings.length}
- Critical: ${findings.filter((f) => f.severity === "critical").length}
- High: ${findings.filter((f) => f.severity === "high").length}
- Medium: ${findings.filter((f) => f.severity === "medium").length}
- Low: ${findings.filter((f) => f.severity === "low").length}

## Architecture
${JSON.stringify(recon.architecture, null, 2)}

## Findings (by severity)
${JSON.stringify(findings, null, 2)}

Format each finding with: severity badge, vulnerability name, affected locations, root cause, exploit path, and recommended fix.
Make it actionable for developers.`,
  { label: "write-report" }
);

return {
  summary: {
    rounds: round,
    areas_covered: coveredAreas.size,
    raw_findings: allFindings.length,
    unique_vulnerabilities: findings.length,
  },
  by_severity: {
    critical: findings.filter((f) => f.severity === "critical").length,
    high: findings.filter((f) => f.severity === "high").length,
    medium: findings.filter((f) => f.severity === "medium").length,
    low: findings.filter((f) => f.severity === "low").length,
  },
  findings,
};
