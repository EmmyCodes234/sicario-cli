"use client";

import { useState, useEffect } from "react";
import { useParams } from "next/navigation";
import { useQuery, useMutation } from "convex/react";
import { findingsGet, findingsTriage } from "@/lib/convexApi";
import type { TriageState } from "@/lib/api";
import { SeverityBadge } from "@/components/SeverityBadge";

const TRIAGE_STATES: TriageState[] = ["Open", "Reviewing", "ToFix", "Fixed", "Ignored", "AutoIgnored"];

export default function FindingDetailPage() {
  const params = useParams();
  const id = params.id as string;
  const finding = useQuery(findingsGet, { id });
  const triage = useMutation(findingsTriage);

  const [triageState, setTriageState] = useState<TriageState>("Open");
  const [triageNote, setTriageNote] = useState("");
  const [assignedTo, setAssignedTo] = useState("");
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (finding) {
      setTriageState(finding.triage_state as TriageState);
      setTriageNote(finding.triage_note || "");
      setAssignedTo(finding.assigned_to || "");
    }
  }, [finding]);

  const handleSave = async () => {
    setSaving(true);
    try {
      await triage({ id, triageState, triageNote: triageNote || undefined, assignedTo: assignedTo || undefined });
    } catch (e) { console.error(e); }
    finally { setSaving(false); }
  };

  if (finding === undefined) return <p>Loading finding...</p>;
  if (finding === null) return <p>Finding not found.</p>;

  const ai = computeAiSuggestion(finding);

  return (
    <>
      <div className="page-header">
        <h1>{finding.rule_name}</h1>
        <p style={{ fontFamily: "monospace" }}>{finding.rule_id}</p>
      </div>

      <div className="grid-2 mb-2">
        <div className="card">
          <h3 className="mb-1">Details</h3>
          <table><tbody>
            <tr><td style={{ color: "var(--text-muted)" }}>Severity</td><td><SeverityBadge severity={finding.severity} /></td></tr>
            <tr><td style={{ color: "var(--text-muted)" }}>Confidence</td><td>{Math.round(finding.confidence_score * 100)}%</td></tr>
            <tr><td style={{ color: "var(--text-muted)" }}>Reachable</td><td>{finding.reachable ? "✅ Yes" : "❌ No"}</td></tr>
            <tr><td style={{ color: "var(--text-muted)" }}>CWE</td><td>{finding.cwe_id || "—"}</td></tr>
            <tr><td style={{ color: "var(--text-muted)" }}>OWASP</td><td>{finding.owasp_category || "—"}</td></tr>
            <tr><td style={{ color: "var(--text-muted)" }}>File</td><td style={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{finding.file_path}:{finding.line}:{finding.column}</td></tr>
            <tr><td style={{ color: "var(--text-muted)" }}>Fingerprint</td><td style={{ fontFamily: "monospace", fontSize: "0.75rem" }}>{finding.fingerprint.substring(0, 16)}…</td></tr>
            <tr><td style={{ color: "var(--text-muted)" }}>Created</td><td>{new Date(finding.created_at).toLocaleString()}</td></tr>
            <tr><td style={{ color: "var(--text-muted)" }}>Updated</td><td>{new Date(finding.updated_at).toLocaleString()}</td></tr>
          </tbody></table>
        </div>

        <div className="card">
          <h3 className="mb-1">Triage</h3>
          <div style={{ background: "rgba(99,102,241,0.08)", border: "1px solid rgba(99,102,241,0.2)", borderRadius: 8, padding: "0.75rem", marginBottom: "1rem" }}>
            <div style={{ fontSize: "0.8rem", color: "var(--accent)", fontWeight: 600, marginBottom: "0.3rem" }}>🤖 AI Triage Suggestion</div>
            <div style={{ fontSize: "0.85rem" }}>{ai.label}</div>
            <div style={{ fontSize: "0.8rem", color: "var(--text-muted)", marginTop: "0.25rem" }}>{ai.reasoning}</div>
          </div>

          <div className="mb-1">
            <label style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>State</label>
            <select className="triage-select" value={triageState} onChange={(e) => setTriageState(e.target.value as TriageState)} style={{ display: "block", width: "100%", marginTop: 4 }}>
              {TRIAGE_STATES.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>
          <div className="mb-1">
            <label style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>Assigned To</label>
            <input value={assignedTo} onChange={(e) => setAssignedTo(e.target.value)} placeholder="username" style={{ display: "block", width: "100%", marginTop: 4 }} />
          </div>
          <div className="mb-1">
            <label style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>Note</label>
            <textarea value={triageNote} onChange={(e) => setTriageNote(e.target.value)} rows={3}
              style={{ display: "block", width: "100%", marginTop: 4, padding: "0.4rem 0.75rem", borderRadius: 8, border: "1px solid var(--border)", background: "var(--bg-card)", color: "var(--text)", fontSize: "0.85rem", resize: "vertical" }} />
          </div>
          <button className="btn btn-primary" onClick={handleSave} disabled={saving} style={{ width: "100%" }}>
            {saving ? "Saving..." : "Save Triage"}
          </button>
        </div>
      </div>

      <div className="card mb-2">
        <h3 className="mb-1">Code Snippet</h3>
        <div className="snippet-code">{finding.snippet || "No snippet available."}</div>
      </div>

      <div className="card">
        <h3 className="mb-1">AI Remediation Guidance</h3>
        <p style={{ fontSize: "0.85rem", color: "var(--text-muted)", marginBottom: "0.5rem" }}>
          Based on rule <strong>{finding.rule_id}</strong> ({finding.cwe_id || "unknown CWE"}):
        </p>
        <div style={{ fontSize: "0.85rem" }}>{getRemediationGuidance(finding)}</div>
      </div>
    </>
  );
}

function computeAiSuggestion(f: any): { label: string; reasoning: string } {
  if (f.reachable && f.confidence_score >= 0.8) return { label: "Likely True Positive — recommend fixing", reasoning: `High confidence (${Math.round(f.confidence_score * 100)}%) with confirmed reachability.` };
  if (f.confidence_score < 0.4) return { label: "Likely False Positive — consider ignoring", reasoning: `Low confidence (${Math.round(f.confidence_score * 100)}%). Generic pattern with no confirmed data-flow path.` };
  if (!f.reachable && f.confidence_score >= 0.5) return { label: "Possible True Positive — needs review", reasoning: `Moderate confidence (${Math.round(f.confidence_score * 100)}%) but no confirmed reachability.` };
  return { label: "Inconclusive — manual review recommended", reasoning: `Confidence: ${Math.round(f.confidence_score * 100)}%, Reachable: ${f.reachable ? "Yes" : "No"}.` };
}

function getRemediationGuidance(f: any): string {
  const r = f.rule_id.toLowerCase();
  if (r.includes("sql")) return "Use parameterized queries or prepared statements instead of string concatenation.";
  if (r.includes("xss")) return "Apply context-appropriate output encoding. Use framework-provided escaping.";
  if (r.includes("cmd") || r.includes("command")) return "Avoid passing user input to shell commands. Use allowlist validation.";
  if (r.includes("ssrf")) return "Validate and allowlist destination URLs. Block internal/private IP ranges.";
  if (r.includes("path") || r.includes("traversal")) return "Sanitize file paths and verify they stay within the expected directory.";
  if (r.includes("crypto") || r.includes("md5") || r.includes("sha1")) return "Use modern algorithms: bcrypt/argon2 for passwords, SHA-256+ for hashing.";
  if (r.includes("deserial")) return "Never deserialize untrusted data without validation. Use safe loaders and schema validation.";
  return "Review the flagged code pattern and apply the appropriate security control. Consult the CWE reference for guidance.";
}
