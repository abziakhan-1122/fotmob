import "server-only";

export async function sendPasswordResetEmail(email: string, token: string) {
  const apiKey = process.env.RESEND_API_KEY;
  const from = process.env.MAIL_FROM;
  const appUrl = process.env.APP_URL || "http://localhost:3000";
  const url = appUrl + "/reset-password?token=" + encodeURIComponent(token);

  if (!apiKey || !from) {
    if (process.env.NODE_ENV !== "production") {
      console.info("[password-reset-dev]", { email, url });
      return;
    }
    throw new Error("Password reset email provider is not configured");
  }

  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: "Bearer " + apiKey, "Content-Type": "application/json" },
    body: JSON.stringify({
      from,
      to: [email],
      subject: "Reset your FotMob password",
      text: "Reset your password using this link: " + url
    })
  });

  if (!response.ok) throw new Error("Unable to send password reset email");
}