import { cronJobs } from "convex/server";
import { internal } from "./_generated/api";

const crons = cronJobs();

// Run SCA dependency scan every 24 hours
crons.daily(
  "scheduled-sca-scan",
  { hourUTC: 3, minuteUTC: 0 }, // 3:00 AM UTC daily
  internal.scheduledScans.runScheduledScaScan
);

// Reset seat counts at the start of each billing period (1st of month, 2:00 AM UTC)
crons.monthly(
  "reset-seat-counts",
  { day: 1, hourUTC: 2, minuteUTC: 0 },
  internal.billing.resetAllSeatCounts,
);

export default crons;
