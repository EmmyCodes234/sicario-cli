import { cronJobs } from "convex/server";
import { internal } from "./_generated/api";

const crons = cronJobs();

// Run SCA dependency scan every 24 hours
crons.daily(
  "scheduled-sca-scan",
  { hourUTC: 3, minuteUTC: 0 }, // 3:00 AM UTC daily
  internal.scheduledScans.runScheduledScaScan
);

export default crons;
