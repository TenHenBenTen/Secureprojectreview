exports.handler = async (event) => {
  try {
    // Only allow POST requests
    if (event.httpMethod !== "POST") {
      return { statusCode: 405, body: "Method Not Allowed" };
    }

    const params = new URLSearchParams(event.body);
    const token = params.get("cf-turnstile-response");
    const honeypot = params.get("company");

    // Honeypot check to trap bots
    if (honeypot) {
      return { statusCode: 403, body: "Bot detected." };
    }

    // If no CAPTCHA token is provided
    if (!token) {
      return { statusCode: 400, body: "Missing CAPTCHA token." };
    }

    // Verify Turnstile CAPTCHA with Cloudflare API
    const verifyResponse = await fetch(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: `secret=${encodeURIComponent(process.env.TURNSTILE_SECRET)}&response=${token}` // Corrected
      }
    );

    const data = await verifyResponse.json();

    // If verification fails
    if (!data.success) {
      return { statusCode: 403, body: "Verification failed." };
    }

    // On success, redirect user to the desired URL
    return {
      statusCode: 302,
      headers: {
        Location: process.env.REDIRECT_URL,  // Corrected
        "Cache-Control": "no-store",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer"
      }
    };

  } catch (error) {
    console.error("Function error:", error);
    return { statusCode: 500, body: "Server error." };
  }
};
