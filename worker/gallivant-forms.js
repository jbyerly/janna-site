// gallivant-forms — contact form + newsletter signup for Janna's site.
// Deploy: wrangler deploy (needs RESEND_API_KEY secret + NOTIFY_TO var)

const ALLOWED_ORIGINS = new Set([
  "https://www.jannalyn.com",
  "https://janna-site.jbyerly2006.workers.dev",
]);

function corsHeaders(req) {
  const origin = req.headers.get("Origin") || "";
  return {
    "Access-Control-Allow-Origin": ALLOWED_ORIGINS.has(origin) ? origin : "https://www.jannalyn.com",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
}

async function sendEmail(env, { to, subject, text, replyTo }) {
  const r = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: "Janna Lyn Travel <noreply@jannalyn.com>",
      to: [to],
      subject,
      text,
      ...(replyTo ? { reply_to: replyTo } : {}),
    }),
  });
  if (!r.ok) throw new Error(`Resend ${r.status}: ${await r.text()}`);
}

async function verifyTurnstile(env, token, ip) {
  if (!env.TURNSTYLE_SECRET && !env.TURNSTILE_SECRET) throw new Error("Turnstile secret not configured");
  const secret = env.TURNSTILE_SECRET || env.TURNSTYLE_SECRET;
  const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ secret, response: token, remoteip: ip || "" }),
  });
  const j = await r.json();
  return j.success === true;
}

async function addToAudience(env, email) {
  // Resend Audiences — create audience "wander-notes" in Resend dashboard first
  const r = await fetch(
    `https://api.resend.com/audiences/${env.RESEND_AUDIENCE_ID}/contacts`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.RESEND_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ email, unsubscribed: false }),
    }
  );
  if (!r.ok && r.status !== 409) throw new Error(`Audience ${r.status}: ${await r.text()}`);
}

export default {
  async fetch(req, env) {
    if (req.method === "OPTIONS")
      return new Response(null, { headers: corsHeaders(req) });
    if (req.method !== "POST")
      return new Response("Method not allowed", { status: 405, headers: corsHeaders(req) });

    const url = new URL(req.url);
    try {
      const data = await req.json();
      const ip = req.headers.get("CF-Connecting-IP") || "";

      // Spam gate: every public submission must pass Turnstile
      if (!data.turnstile || !(await verifyTurnstile(env, data.turnstile, ip)))
        return Response.json({ ok: false, error: "Spam check failed — please try again." }, { status: 403, headers: corsHeaders(req) });

      if (url.pathname === "/contact") {
        const { name, email, trip_type, message } = data;
        if (!name || !email || !message)
          return Response.json({ ok: false, error: "Missing fields" }, { status: 400, headers: corsHeaders(req) });
        await sendEmail(env, {
          to: env.NOTIFY_TO,
          replyTo: email,
          subject: `New trip inquiry from ${name}`,
          text: `Name: ${name}\nEmail: ${email}\nTrip type: ${trip_type || "—"}\n\n${message}`,
        });
        return Response.json({ ok: true }, { headers: corsHeaders(req) });
      }

      if (url.pathname === "/newsletter") {
        const { email } = data;
        if (!email || !email.includes("@"))
          return Response.json({ ok: false, error: "Bad email" }, { status: 400, headers: corsHeaders(req) });
        await addToAudience(env, email);
        await sendEmail(env, {
          to: env.NOTIFY_TO,
          subject: "New Wander Notes signup",
          text: `${email} joined the Wander Notes email list.`,
        });
        return Response.json({ ok: true }, { headers: corsHeaders(req) });
      }

      return Response.json({ ok: false, error: "Unknown route" }, { status: 404, headers: corsHeaders(req) });
    } catch (e) {
      return Response.json({ ok: false, error: String(e.message || e) }, { status: 500, headers: corsHeaders(req) });
    }
  },
};
