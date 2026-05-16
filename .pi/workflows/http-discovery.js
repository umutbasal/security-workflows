export const meta = {
  name: "http-discovery",
  description: "Scan targets from list.txt on common HTTP ports with naabu, then probe live URLs with httpx",
  phases: [
    { title: "Scan", detail: "port scan targets with naabu" },
    { title: "Probe", detail: "check HTTP availability with httpx" },
    { title: "Report", detail: "compile results" },
  ],
};

export default async function ({ agent, step, log, args }) {
  const targetFile = args?.targets || "list.txt";
  const ports = args?.ports || "80,443,8080,8443,8000,8888,3000,5000,9090,8081,8082,8443,4443,2443";

  log(`Scanning targets from ${targetFile} on HTTP ports: ${ports}`);

  const scanResults = await agent(
    `Run naabu to scan the targets in "${targetFile}" for these specific ports: ${ports}.
    
    Use this command:
    naabu -list ${targetFile} -p ${ports} -silent -o /tmp/naabu-results.txt
    
    Then read /tmp/naabu-results.txt and return the results.
    If naabu is not installed, try to run it anyway (it may be in PATH).
    Return the raw output lines (each line is host:port).`,
    {
      label: "naabu-scan",
      phase: "Scan",
      schema: {
        type: "array",
        items: { type: "string" },
      },
    }
  );

  if (!scanResults || scanResults.length === 0) {
    log("No open ports found. Nothing to probe.");
    return { open_ports: 0, live_urls: 0, results: [] };
  }

  log(`Found ${scanResults.length} open host:port pairs. Probing with httpx...`);

  const httpxResults = await agent(
    `The following host:port pairs were found open by naabu:
${scanResults.join("\n")}

Write these to /tmp/httpx-targets.txt (one per line), then run httpx against them:
httpx -l /tmp/httpx-targets.txt -silent -status-code -title -tech-detect -o /tmp/httpx-results.txt

Then read /tmp/httpx-results.txt and return the results as structured data.
Each result should include the url, status_code, title, and technologies if available.`,
    {
      label: "httpx-probe",
      phase: "Probe",
      schema: {
        type: "array",
        items: {
          type: "object",
          properties: {
            url: { type: "string" },
            status_code: { type: "number" },
            title: { type: "string" },
            technologies: { type: "array", items: { type: "string" } },
          },
        },
      },
    }
  );

  return await step("compile-report", "Report", () => {
    const live = httpxResults?.filter((r) => r && r.status_code) || [];
    log(`Probe complete: ${live.length} live URLs out of ${scanResults.length} open ports`);

    return {
      target_file: targetFile,
      ports_scanned: ports,
      open_ports_found: scanResults.length,
      live_urls: live.length,
      results: live,
    };
  });
}
