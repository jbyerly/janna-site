// decap-oauth — GitHub OAuth gateway for Decap CMS, on Cloudflare Workers.
//
// Why: GitHub OAuth needs a client secret, which can't live in a static page.
// This Worker holds the secret and hands Decap a token via postMessage.
//
// Deploy: npx wrangler deploy decap-oauth.js --name decap-oauth
// Secrets:  npx wrangler secret put GITHUB_CLIENT_SECRET
// Vars:     GITHUB_CLIENT_ID (from the GitHub OAuth App)

function randomState() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);

    // Step 1: start login — bounce the popup to GitHub
    if (url.pathname === "/auth") {
      const state = randomState();
      const params = new URLSearchParams({
        client_id: env.GITHUB_CLIENT_ID,
        redirect_uri: `${url.origin}/callback`,
        scope: "repo",
        state,
      });
      return new Response(null, {
        status: 302,
        headers: {
          Location: `https://github.com/login/oauth/authorize?${params}`,
          "Set-Cookie": `decap_oauth_state=${state}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600`,
        },
      });
    }

    // Step 2: GitHub redirects back with a code — trade it for a token
    if (url.pathname === "/callback") {
      const code = url.searchParams.get("code");
      const state = url.searchParams.get("state");
      const cookie = req.headers.get("Cookie") || "";
      const m = cookie.match(/decap_oauth_state=([^;]+)/);
      if (!code || !state || !m || m[1] !== state)
        return new Response("Invalid OAuth state — please try signing in again.", { status: 403 });

      const tokenRes = await fetch("https://github.com/login/oauth/access_token", {
        method: "POST",
        headers: { Accept: "application/json", "Content-Type": "application/json" },
        body: JSON.stringify({
          client_id: env.GITHUB_CLIENT_ID,
          client_secret: env.GITHUB_CLIENT_SECRET,
          code,
          redirect_uri: `${url.origin}/callback`,
        }),
      });
      const tok = await tokenRes.json();
      if (!tok.access_token)
        return new Response("GitHub sign-in failed — please try again.", { status: 502 });

      // Decap listens for this exact message in the popup
      const payload = JSON.stringify({ token: tok.access_token, provider: "github" });
      const html = `<!doctype html><html><body><script>
(function(){var msg="authorization:github:success:"+${JSON.stringify(payload)};
if(window.opener){window.opener.postMessage(msg,"*");}window.close();})();
</script><p>Signed in — you can close this window.</p></body></html>`;
      return new Response(html, {
        headers: {
          "Content-Type": "text/html",
          "Set-Cookie": "decap_oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0",
        },
      });
    }

    return new Response("Not found", { status: 404 });
  },
};
