"use client";

import { useQuery } from "convex/react";
import { projectsList } from "@/lib/convexApi";

export default function ProjectsPage() {
  const projects = useQuery(projectsList, {});

  if (projects === undefined) return <p>Loading projects...</p>;

  return (
    <>
      <div className="page-header"><h1>Projects</h1><p>Repositories and applications being scanned</p></div>
      <div className="card">
        {projects.length === 0 ? (
          <p style={{ color: "var(--text-muted)" }}>No projects configured. Publish a scan with <code>sicario publish</code> to get started.</p>
        ) : (
          <table>
            <thead><tr><th>Name</th><th>Repository</th><th>Team</th><th>Created</th></tr></thead>
            <tbody>
              {projects.map((p: any) => (
                <tr key={p.id}>
                  <td>{p.name}</td>
                  <td style={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{p.repository_url || "—"}</td>
                  <td>{p.team_id || "—"}</td>
                  <td>{new Date(p.created_at).toLocaleDateString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
