export default {
  providers: [
    {
      domain: process.env.SITE_URL ?? process.env.CONVEX_SITE_URL,
      applicationID: "convex",
    },
  ],
};
