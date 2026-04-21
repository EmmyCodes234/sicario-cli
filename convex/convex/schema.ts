import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

export default defineSchema({
  organizations: defineTable({
    orgId: v.string(),
    name: v.string(),
    createdAt: v.string(),
  }).index("by_orgId", ["orgId"]),

  teams: defineTable({
    teamId: v.string(),
    name: v.string(),
    orgId: v.string(),
    createdAt: v.string(),
  })
    .index("by_teamId", ["teamId"])
    .index("by_orgId", ["orgId"]),

  projects: defineTable({
    projectId: v.string(),
    name: v.string(),
    repositoryUrl: v.string(),
    description: v.string(),
    teamId: v.optional(v.string()),
    createdAt: v.string(),
  })
    .index("by_projectId", ["projectId"])
    .index("by_teamId", ["teamId"]),

  scans: defineTable({
    scanId: v.string(),
    repository: v.string(),
    branch: v.string(),
    commitSha: v.string(),
    timestamp: v.string(),
    durationMs: v.number(),
    rulesLoaded: v.number(),
    filesScanned: v.number(),
    languageBreakdown: v.any(),
    tags: v.array(v.string()),
    projectId: v.optional(v.string()),
    createdAt: v.string(),
  })
    .index("by_scanId", ["scanId"])
    .index("by_repository", ["repository"])
    .index("by_timestamp", ["timestamp"]),

  findings: defineTable({
    findingId: v.string(),
    scanId: v.string(),
    ruleId: v.string(),
    ruleName: v.string(),
    filePath: v.string(),
    line: v.number(),
    column: v.number(),
    endLine: v.optional(v.number()),
    endColumn: v.optional(v.number()),
    snippet: v.string(),
    severity: v.string(),
    confidenceScore: v.number(),
    reachable: v.boolean(),
    cloudExposed: v.optional(v.boolean()),
    cweId: v.optional(v.string()),
    owaspCategory: v.optional(v.string()),
    fingerprint: v.string(),
    triageState: v.string(),
    triageNote: v.optional(v.string()),
    assignedTo: v.optional(v.string()),
    createdAt: v.string(),
    updatedAt: v.string(),
  })
    .index("by_findingId", ["findingId"])
    .index("by_scanId", ["scanId"])
    .index("by_severity", ["severity"])
    .index("by_triageState", ["triageState"])
    .index("by_fingerprint", ["fingerprint"])
    .index("by_createdAt", ["createdAt"]),

  webhooks: defineTable({
    webhookId: v.string(),
    orgId: v.string(),
    url: v.string(),
    events: v.array(v.string()),
    deliveryType: v.string(),
    secret: v.optional(v.string()),
    enabled: v.boolean(),
    createdAt: v.string(),
  })
    .index("by_webhookId", ["webhookId"])
    .index("by_orgId", ["orgId"]),

  webhookDeliveries: defineTable({
    deliveryId: v.string(),
    webhookId: v.string(),
    eventType: v.string(),
    payload: v.any(),
    status: v.string(),
    responseCode: v.optional(v.number()),
    deliveredAt: v.string(),
  })
    .index("by_webhookId", ["webhookId"])
    .index("by_deliveredAt", ["deliveredAt"]),

  memberships: defineTable({
    userId: v.string(),
    orgId: v.string(),
    role: v.string(), // "admin" | "manager" | "developer"
    teamIds: v.array(v.string()),
    createdAt: v.string(),
  })
    .index("by_userId", ["userId"])
    .index("by_orgId", ["orgId"])
    .index("by_userId_orgId", ["userId", "orgId"]),

  ssoConfigs: defineTable({
    orgId: v.string(),
    provider: v.string(), // "saml" | "oidc"
    issuerUrl: v.string(),
    clientId: v.string(),
    metadataUrl: v.optional(v.string()),
    enabled: v.boolean(),
    createdAt: v.string(),
  }).index("by_orgId", ["orgId"]),
});
