import initializeApp from "./shared/services/initializeApp.js";

function validateSecurityEnv() {
  const requiredEnvs = ["JWT_SECRET", "API_KEY_SECRET"];
  const missing = requiredEnvs.filter((key) => !process.env[key]);

  if (missing.length > 0) {
    throw new Error(`Missing required security env: ${missing.join(", ")}`);
  }
}

async function startServer() {
  console.log("Starting server...");

  try {
    validateSecurityEnv();
    await initializeApp();
    console.log("Server initialized");
  } catch (error) {
    console.log("Error initializing server:", error);
    process.exit(1);
  }
}

startServer().catch(console.log);

export default startServer;
