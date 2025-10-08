import { serve } from "https://deno.land/std/http/server.ts";
import * as admin from "npm:firebase-admin";

const firebaseApp = admin.apps.length
  ? admin.app()
  : admin.initializeApp({
      credential: admin.credential.cert({
        projectId: Deno.env.get("FIREBASE_PROJECT_ID"),
        clientEmail: Deno.env.get("FIREBASE_CLIENT_EMAIL"),
        privateKey: Deno.env.get("FIREBASE_PRIVATE_KEY")?.replace(/\\n/g, "\n"),
      }),
    });

const FIREBASE_WEB_API_KEY = process.env.FIREBASE_API_KEY;

serve(async (req) => {
  try {
    const { email, password } = await req.json();
    if (!email || !password)
      return new Response("Email and password required", { status: 400 });

    const res = await fetch(
      `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${FIREBASE_WEB_API_KEY}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password, returnSecureToken: true }),
      }
    );

    const json = await res.json();
    if (json.error)
      return new Response(JSON.stringify(json), { status: 400 });

    return new Response(JSON.stringify(json), {
      headers: { "Content-Type": "application/json" },
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: String(err) }), {
      headers: { "Content-Type": "application/json" },
      status: 500,
    });
  }
});
