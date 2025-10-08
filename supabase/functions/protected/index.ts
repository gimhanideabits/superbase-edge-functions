import { serve } from "https://deno.land/std/http/server.ts";
import { createClient } from "@supabase/supabase-js";
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

const supabase = createClient(
  Deno.env.get("PROJECT_URL")!,
  Deno.env.get("SERVICE_ROLE_KEY")!
);

serve(async (req) => {
  try {
    const authHeader = req.headers.get("authorization");
    if (!authHeader)
      return new Response("Missing Authorization header", { status: 401 });

    const token = authHeader.replace("Bearer ", "");
    
    const decoded = await firebaseApp.auth().verifyIdToken(token);
    
    const { data, error } = await supabase
      .from("users")
      .select("*")
      .eq("uid", decoded.uid)
      .single();

    if (error) throw error;

    return new Response(JSON.stringify({ user: data }), {
      headers: { "Content-Type": "application/json" },
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: String(err) }), {
      headers: { "Content-Type": "application/json" },
      status: 401,
    });
  }
});
