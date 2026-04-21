"use client";

import { useQuery, useMutation } from "convex/react";
import { useState } from "react";
import {
  membershipsList,
  membershipsCreate,
  membershipsUpdate,
  membershipsRemove,
  ssoGetConfig,
  ssoConfigure,
  ssoDisable,
  ssoListProviders,
  teamsList,
  projectsList,
} from "@/lib/convexApi";
import type { Role, SsoProvider } from "@/lib/api";

// Placeholder auth context — in production this comes from JWT/session
const CURRENT_USER_ID = "current-user";
const CURRENT_ORG_ID = "default-org";

export default function SettingsPage() {
  const [activeTab, setActiveTab] = useState<"members" | "sso" | "hierarchy">("members");

  return (
    <div>
      <h1 style={{ marginBottom: "1.5rem" }}>⚙️ Organization Settings</h1>
      <p style={{ color: "#888", marginBottom: "1.5rem" }}>
        Admin-only settings for team management, SSO configuration, and org hierarchy.
      </p>

      <div style={{ display: "flex", gap: "0.5rem", marginBottom: "2rem" }}>
        {(["members", "sso", "hierarchy"] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            style={{
              padding: "0.5rem 1rem",
              borderRadius: "6px",
              border: activeTab === tab ? "2px solid #3b82f6" : "1px solid #333",
              background: activeTab === tab ? "#1e3a5f" : "#1a1a2e",
              color: activeTab === tab ? "#60a5fa" : "#ccc",
              cursor: "pointer",
              fontWeight: activeTab === tab ? 600 : 400,
            }}
          >
            {tab === "members" ? "👥 Team Members" : tab === "sso" ? "🔐 SSO" : "🏢 Hierarchy"}
          </button>
        ))}
      </div>

      {activeTab === "members" && <MembersPanel />}
      {activeTab === "sso" && <SsoPanel />}
      {activeTab === "hierarchy" && <HierarchyPanel />}
    </div>
  );
}

function MembersPanel() {
  const members = useQuery(membershipsList, {
    orgId: CURRENT_ORG_ID,
    userId: CURRENT_USER_ID,
  });
  const createMember = useMutation(membershipsCreate);
  const updateMember = useMutation(membershipsUpdate);
  const removeMember = useMutation(membershipsRemove);

  const [showAdd, setShowAdd] = useState(false);
  const [newUserId, setNewUserId] = useState("");
  const [newRole, setNewRole] = useState<Role>("developer");

  const handleAdd = async () => {
    if (!newUserId.trim()) return;
    await createMember({
      callerUserId: CURRENT_USER_ID,
      orgId: CURRENT_ORG_ID,
      userId: newUserId.trim(),
      role: newRole,
      teamIds: [],
    });
    setNewUserId("");
    setShowAdd(false);
  };

  const handleRoleChange = async (userId: string, role: Role) => {
    await updateMember({
      callerUserId: CURRENT_USER_ID,
      orgId: CURRENT_ORG_ID,
      userId,
      role,
    });
  };

  const handleRemove = async (userId: string) => {
    if (!confirm(`Remove user ${userId} from the organization?`)) return;
    await removeMember({
      callerUserId: CURRENT_USER_ID,
      orgId: CURRENT_ORG_ID,
      userId,
    });
  };

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem" }}>
        <h2>Team Members</h2>
        <button
          onClick={() => setShowAdd(!showAdd)}
          style={{
            padding: "0.4rem 1rem",
            borderRadius: "6px",
            border: "1px solid #3b82f6",
            background: "#1e3a5f",
            color: "#60a5fa",
            cursor: "pointer",
          }}
        >
          + Add Member
        </button>
      </div>

      {showAdd && (
        <div style={{ display: "flex", gap: "0.5rem", marginBottom: "1rem", alignItems: "center" }}>
          <input
            type="text"
            placeholder="User ID or email"
            value={newUserId}
            onChange={(e) => setNewUserId(e.target.value)}
            style={{
              padding: "0.4rem 0.75rem",
              borderRadius: "6px",
              border: "1px solid #333",
              background: "#0d0d1a",
              color: "#eee",
              flex: 1,
            }}
          />
          <select
            value={newRole}
            onChange={(e) => setNewRole(e.target.value as Role)}
            style={{
              padding: "0.4rem 0.75rem",
              borderRadius: "6px",
              border: "1px solid #333",
              background: "#0d0d1a",
              color: "#eee",
            }}
          >
            <option value="developer">Developer</option>
            <option value="manager">Manager</option>
            <option value="admin">Admin</option>
          </select>
          <button
            onClick={handleAdd}
            style={{
              padding: "0.4rem 1rem",
              borderRadius: "6px",
              border: "none",
              background: "#22c55e",
              color: "#fff",
              cursor: "pointer",
            }}
          >
            Add
          </button>
        </div>
      )}

      <table style={{ width: "100%", borderCollapse: "collapse" }}>
        <thead>
          <tr style={{ borderBottom: "1px solid #333" }}>
            <th style={{ textAlign: "left", padding: "0.5rem" }}>User</th>
            <th style={{ textAlign: "left", padding: "0.5rem" }}>Role</th>
            <th style={{ textAlign: "left", padding: "0.5rem" }}>Teams</th>
            <th style={{ textAlign: "left", padding: "0.5rem" }}>Joined</th>
            <th style={{ textAlign: "right", padding: "0.5rem" }}>Actions</th>
          </tr>
        </thead>
        <tbody>
          {members === undefined ? (
            <tr><td colSpan={5} style={{ padding: "1rem", color: "#888" }}>Loading...</td></tr>
          ) : members.length === 0 ? (
            <tr><td colSpan={5} style={{ padding: "1rem", color: "#888" }}>No members yet.</td></tr>
          ) : (
            members.map((m: any) => (
              <tr key={m.user_id} style={{ borderBottom: "1px solid #222" }}>
                <td style={{ padding: "0.5rem" }}>{m.user_id}</td>
                <td style={{ padding: "0.5rem" }}>
                  <select
                    value={m.role}
                    onChange={(e) => handleRoleChange(m.user_id, e.target.value as Role)}
                    style={{
                      padding: "0.25rem 0.5rem",
                      borderRadius: "4px",
                      border: "1px solid #333",
                      background: "#0d0d1a",
                      color: "#eee",
                    }}
                  >
                    <option value="developer">Developer</option>
                    <option value="manager">Manager</option>
                    <option value="admin">Admin</option>
                  </select>
                </td>
                <td style={{ padding: "0.5rem", color: "#888" }}>
                  {m.team_ids.length > 0 ? m.team_ids.join(", ") : "—"}
                </td>
                <td style={{ padding: "0.5rem", color: "#888" }}>
                  {new Date(m.created_at).toLocaleDateString()}
                </td>
                <td style={{ padding: "0.5rem", textAlign: "right" }}>
                  <button
                    onClick={() => handleRemove(m.user_id)}
                    style={{
                      padding: "0.25rem 0.5rem",
                      borderRadius: "4px",
                      border: "1px solid #ef4444",
                      background: "transparent",
                      color: "#ef4444",
                      cursor: "pointer",
                      fontSize: "0.85rem",
                    }}
                  >
                    Remove
                  </button>
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}

function SsoPanel() {
  const ssoConfig = useQuery(ssoGetConfig, {
    orgId: CURRENT_ORG_ID,
    userId: CURRENT_USER_ID,
  });
  const providers = useQuery(ssoListProviders);
  const configureSso = useMutation(ssoConfigure);
  const disableSso = useMutation(ssoDisable);

  const [provider, setProvider] = useState<SsoProvider>("oidc");
  const [issuerUrl, setIssuerUrl] = useState("");
  const [clientId, setClientId] = useState("");
  const [metadataUrl, setMetadataUrl] = useState("");

  const handleConfigure = async () => {
    if (!issuerUrl.trim() || !clientId.trim()) return;
    await configureSso({
      userId: CURRENT_USER_ID,
      orgId: CURRENT_ORG_ID,
      provider,
      issuerUrl: issuerUrl.trim(),
      clientId: clientId.trim(),
      metadataUrl: metadataUrl.trim() || undefined,
    });
    setIssuerUrl("");
    setClientId("");
    setMetadataUrl("");
  };

  const handleDisable = async () => {
    if (!confirm("Disable SSO for this organization?")) return;
    await disableSso({
      userId: CURRENT_USER_ID,
      orgId: CURRENT_ORG_ID,
    });
  };

  const inputStyle = {
    padding: "0.4rem 0.75rem",
    borderRadius: "6px",
    border: "1px solid #333",
    background: "#0d0d1a",
    color: "#eee",
    width: "100%",
  };

  return (
    <div>
      <h2 style={{ marginBottom: "1rem" }}>Single Sign-On (SSO)</h2>

      {ssoConfig && ssoConfig.enabled ? (
        <div style={{
          padding: "1rem",
          borderRadius: "8px",
          border: "1px solid #22c55e",
          background: "#0d2818",
          marginBottom: "1.5rem",
        }}>
          <p style={{ color: "#22c55e", fontWeight: 600, marginBottom: "0.5rem" }}>
            ✅ SSO is enabled
          </p>
          <p style={{ color: "#ccc" }}>
            Provider: <strong>{ssoConfig.provider.toUpperCase()}</strong>
          </p>
          <p style={{ color: "#ccc" }}>
            Issuer: <strong>{ssoConfig.issuer_url}</strong>
          </p>
          <p style={{ color: "#ccc" }}>
            Client ID: <strong>{ssoConfig.client_id}</strong>
          </p>
          {ssoConfig.metadata_url && (
            <p style={{ color: "#ccc" }}>
              Metadata URL: <strong>{ssoConfig.metadata_url}</strong>
            </p>
          )}
          <button
            onClick={handleDisable}
            style={{
              marginTop: "0.75rem",
              padding: "0.4rem 1rem",
              borderRadius: "6px",
              border: "1px solid #ef4444",
              background: "transparent",
              color: "#ef4444",
              cursor: "pointer",
            }}
          >
            Disable SSO
          </button>
        </div>
      ) : (
        <p style={{ color: "#888", marginBottom: "1rem" }}>
          SSO is not configured. Set up SAML 2.0 or OpenID Connect below.
        </p>
      )}

      <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem", maxWidth: "500px" }}>
        <div>
          <label style={{ display: "block", marginBottom: "0.25rem", color: "#aaa", fontSize: "0.85rem" }}>
            Provider
          </label>
          <select
            value={provider}
            onChange={(e) => setProvider(e.target.value as SsoProvider)}
            style={inputStyle}
          >
            {(providers ?? ["saml", "oidc"]).map((p: any) => (
              <option key={p} value={p}>{p === "saml" ? "SAML 2.0" : "OpenID Connect"}</option>
            ))}
          </select>
        </div>
        <div>
          <label style={{ display: "block", marginBottom: "0.25rem", color: "#aaa", fontSize: "0.85rem" }}>
            Issuer URL
          </label>
          <input
            type="url"
            placeholder="https://idp.example.com"
            value={issuerUrl}
            onChange={(e) => setIssuerUrl(e.target.value)}
            style={inputStyle}
          />
        </div>
        <div>
          <label style={{ display: "block", marginBottom: "0.25rem", color: "#aaa", fontSize: "0.85rem" }}>
            Client ID
          </label>
          <input
            type="text"
            placeholder="your-client-id"
            value={clientId}
            onChange={(e) => setClientId(e.target.value)}
            style={inputStyle}
          />
        </div>
        {provider === "saml" && (
          <div>
            <label style={{ display: "block", marginBottom: "0.25rem", color: "#aaa", fontSize: "0.85rem" }}>
              SAML Metadata URL (optional)
            </label>
            <input
              type="url"
              placeholder="https://idp.example.com/metadata.xml"
              value={metadataUrl}
              onChange={(e) => setMetadataUrl(e.target.value)}
              style={inputStyle}
            />
          </div>
        )}
        <button
          onClick={handleConfigure}
          style={{
            padding: "0.5rem 1rem",
            borderRadius: "6px",
            border: "none",
            background: "#3b82f6",
            color: "#fff",
            cursor: "pointer",
            fontWeight: 600,
            alignSelf: "flex-start",
          }}
        >
          {ssoConfig?.enabled ? "Update SSO Configuration" : "Enable SSO"}
        </button>
      </div>
    </div>
  );
}

function HierarchyPanel() {
  const teams = useQuery(teamsList);
  const projects = useQuery(projectsList);

  return (
    <div>
      <h2 style={{ marginBottom: "1rem" }}>Organization Hierarchy</h2>
      <p style={{ color: "#888", marginBottom: "1.5rem" }}>
        Organization → Teams → Projects. Permissions are inherited downward.
        Admins can access all teams and projects. Managers and developers can only
        access their assigned teams and the projects within them.
      </p>

      <div style={{
        padding: "1rem",
        borderRadius: "8px",
        border: "1px solid #333",
        background: "#1a1a2e",
      }}>
        <div style={{ fontWeight: 600, fontSize: "1.1rem", marginBottom: "1rem" }}>
          🏢 {CURRENT_ORG_ID}
        </div>

        {teams === undefined ? (
          <p style={{ color: "#888" }}>Loading teams...</p>
        ) : teams.length === 0 ? (
          <p style={{ color: "#888", marginLeft: "1.5rem" }}>No teams created yet.</p>
        ) : (
          teams.map((team: any) => {
            const teamProjects = (projects ?? []).filter((p: any) => p.team_id === team.id);
            return (
              <div key={team.id} style={{ marginLeft: "1.5rem", marginBottom: "0.75rem" }}>
                <div style={{ fontWeight: 500, color: "#60a5fa" }}>
                  👥 {team.name} <span style={{ color: "#666", fontSize: "0.85rem" }}>({team.id})</span>
                </div>
                {teamProjects.length > 0 ? (
                  teamProjects.map((proj: any) => (
                    <div key={proj.id} style={{ marginLeft: "1.5rem", color: "#ccc", fontSize: "0.9rem" }}>
                      📁 {proj.name} <span style={{ color: "#666", fontSize: "0.8rem" }}>({proj.id})</span>
                    </div>
                  ))
                ) : (
                  <div style={{ marginLeft: "1.5rem", color: "#666", fontSize: "0.85rem" }}>
                    No projects in this team
                  </div>
                )}
              </div>
            );
          })
        )}

        {/* Show unassigned projects */}
        {projects && projects.filter((p: any) => !p.team_id).length > 0 && (
          <div style={{ marginLeft: "1.5rem", marginTop: "0.75rem" }}>
            <div style={{ fontWeight: 500, color: "#f59e0b" }}>📁 Unassigned Projects</div>
            {projects.filter((p: any) => !p.team_id).map((proj: any) => (
              <div key={proj.id} style={{ marginLeft: "1.5rem", color: "#ccc", fontSize: "0.9rem" }}>
                📁 {proj.name} <span style={{ color: "#666", fontSize: "0.8rem" }}>({proj.id})</span>
              </div>
            ))}
          </div>
        )}
      </div>

      <div style={{ marginTop: "1.5rem", padding: "1rem", borderRadius: "8px", border: "1px solid #333", background: "#1a1a2e" }}>
        <h3 style={{ marginBottom: "0.5rem" }}>Role Permissions</h3>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ borderBottom: "1px solid #333" }}>
              <th style={{ textAlign: "left", padding: "0.5rem" }}>Permission</th>
              <th style={{ textAlign: "center", padding: "0.5rem" }}>Admin</th>
              <th style={{ textAlign: "center", padding: "0.5rem" }}>Manager</th>
              <th style={{ textAlign: "center", padding: "0.5rem" }}>Developer</th>
            </tr>
          </thead>
          <tbody>
            {[
              { perm: "Manage teams", admin: true, manager: false, dev: false },
              { perm: "Configure SSO & webhooks", admin: true, manager: false, dev: false },
              { perm: "Manage members & roles", admin: true, manager: false, dev: false },
              { perm: "Create/update projects", admin: true, manager: true, dev: false },
              { perm: "View all team projects", admin: true, manager: true, dev: false },
              { perm: "Triage findings", admin: true, manager: true, dev: true },
              { perm: "View assigned projects", admin: true, manager: true, dev: true },
              { perm: "Apply fixes & publish scans", admin: true, manager: true, dev: true },
            ].map((row) => (
              <tr key={row.perm} style={{ borderBottom: "1px solid #222" }}>
                <td style={{ padding: "0.5rem" }}>{row.perm}</td>
                <td style={{ padding: "0.5rem", textAlign: "center" }}>{row.admin ? "✅" : "—"}</td>
                <td style={{ padding: "0.5rem", textAlign: "center" }}>{row.manager ? "✅" : "—"}</td>
                <td style={{ padding: "0.5rem", textAlign: "center" }}>{row.dev ? "✅" : "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
