import { NextResponse } from "next/server";
import { jwtVerify } from "jose";
import { getSettings } from "@/lib/localDb";

function parseCookie(headerValue = "") {
  const cookieMap = {};
  for (const part of headerValue.split(";")) {
    const [rawKey, ...rest] = part.trim().split("=");
    if (!rawKey) continue;
    cookieMap[rawKey] = rest.join("=");
  }
  return cookieMap;
}

function getJwtSecret() {
  const jwtSecret = process.env.JWT_SECRET;
  if (!jwtSecret) return null;
  return new TextEncoder().encode(jwtSecret);
}

export async function requireDashboardAuth(request) {
  const settings = await getSettings();
  const requireLogin = settings.requireLogin !== false;

  if (!requireLogin) {
    return { ok: true, requireLogin: false };
  }

  const secret = getJwtSecret();
  if (!secret) {
    return {
      ok: false,
      status: 503,
      response: NextResponse.json(
        { error: "Server misconfigured: JWT_SECRET is required when login is enabled" },
        { status: 503 }
      ),
    };
  }

  const cookies = parseCookie(request.headers.get("cookie") || "");
  const token = cookies.auth_token;

  if (!token) {
    return {
      ok: false,
      status: 401,
      response: NextResponse.json({ error: "Unauthorized" }, { status: 401 }),
    };
  }

  try {
    await jwtVerify(token, secret);
    return { ok: true, requireLogin: true };
  } catch {
    return {
      ok: false,
      status: 401,
      response: NextResponse.json({ error: "Unauthorized" }, { status: 401 }),
    };
  }
}
