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
  Deno.env.get("ROLE_KEY")!
);

serve(async (req) => {
  try {
    const { email, password } = await req.json();

    if (!email || !password)
      return new Response("Email and password required", { status: 400 });


    const userRecord = await firebaseApp.auth().createUser({
      email,
      password,
    });

 
    const customToken = await firebaseApp.auth().createCustomToken(userRecord.uid);

    const { data, error } = await supabase
      .from("users")
      .insert([{ uid: userRecord.uid, email }])
      .select();

    if (error) throw error;

    return new Response(
      JSON.stringify({
        message: "User created successfully",
        firebase_uid: userRecord.uid,
        token: customToken,
      }),
      { headers: { "Content-Type": "application/json" }, status: 201 }
    );
  } catch (err) {
    return new Response(JSON.stringify({ error: String(err) }), {
      headers: { "Content-Type": "application/json" },
      status: 500,
    });
  }
});
