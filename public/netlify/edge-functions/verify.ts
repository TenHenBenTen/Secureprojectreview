export default async (request: Request) => {

  if (request.method !== "POST") {
    return new Response("Method Not Allowed", { status: 405 });
  }

  const body = await request.json();
  const token = body.token;

  if (!token) {
    return new Response("Forbidden", { status: 403 });
  }

  // Verify Turnstile with Cloudflare
  const formData = new URLSearchParams();
  formData.append("secret", Deno.env.get("TURNSTILE_SECRET_KEY")!);
  formData.append("response", token);

  const verify = await fetch(
    "https://challenges.cloudflare.com/turnstile/v0/siteverify",
    {
      method: "POST",
      body: formData
    }
  );

  const data = await verify.json();

  if (!data.success) {
    return new Response("Bot detected", { status: 403 });
  }

  // Optional: Check bot score header from Cloudflare
  const botScore = request.headers.get("cf-bot-score");

  if (botScore && Number(botScore) < 30) {
    return new Response("Low bot score", { status: 403 });
  }

  return Response.redirect(
    Deno.env.get("REAL_REDIRECT_URL")!,
    302
  );
};
