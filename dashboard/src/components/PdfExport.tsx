"use client";

import type { AnalyticsOverview, MttrMetrics } from "@/lib/api";

/**
 * Generates a PDF report from the current dashboard overview data.
 * Uses jsPDF + jspdf-autotable for table rendering.
 * Requirement 21.13: PDF export for stakeholder presentations.
 */
export async function exportOverviewPdf(overview: AnalyticsOverview, mttr: MttrMetrics) {
  const { jsPDF } = await import("jspdf");
  await import("jspdf-autotable");

  const doc = new jsPDF();
  const now = new Date().toLocaleDateString();

  // Title
  doc.setFontSize(20);
  doc.setTextColor(99, 102, 241);
  doc.text("Sicario Security Report", 14, 22);
  doc.setFontSize(10);
  doc.setTextColor(136, 136, 160);
  doc.text(`Generated ${now}`, 14, 30);

  // Summary table
  doc.setFontSize(14);
  doc.setTextColor(228, 228, 239);
  doc.text("Findings Summary", 14, 44);

  (doc as any).autoTable({
    startY: 48,
    head: [["Metric", "Value"]],
    body: [
      ["Total Findings", String(overview.total_findings)],
      ["Open", String(overview.open_findings)],
      ["Fixed", String(overview.fixed_findings)],
      ["Ignored", String(overview.ignored_findings)],
      ["Critical", String(overview.critical_count)],
      ["High", String(overview.high_count)],
      ["Medium", String(overview.medium_count)],
      ["Low", String(overview.low_count)],
      ["Info", String(overview.info_count)],
      ["Total Scans", String(overview.total_scans)],
      ["Avg Scan Duration (ms)", String(overview.avg_scan_duration_ms)],
    ],
    theme: "grid",
    headStyles: { fillColor: [99, 102, 241] },
    styles: { fontSize: 9 },
  });

  // MTTR section
  const finalY = (doc as any).lastAutoTable?.finalY || 160;
  doc.setFontSize(14);
  doc.text("Mean Time to Resolve", 14, finalY + 14);

  const mttrRows = [["Overall", `${mttr.overall_mttr_hours.toFixed(1)} hours`]];
  Object.entries(mttr.by_severity).forEach(([sev, hours]) => {
    mttrRows.push([sev, `${hours.toFixed(1)} hours`]);
  });

  (doc as any).autoTable({
    startY: finalY + 18,
    head: [["Severity", "MTTR"]],
    body: mttrRows,
    theme: "grid",
    headStyles: { fillColor: [99, 102, 241] },
    styles: { fontSize: 9 },
  });

  doc.save("sicario-report.pdf");
}
