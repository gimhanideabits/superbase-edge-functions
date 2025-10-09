import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

// CORS headers
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

serve(async (req) => {
  // Handle CORS preflight requests
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }

  try {
    // Parse request body
    const { email, password } = await req.json()

    // Validate input
    if (!email || !password) {
      return new Response(
        JSON.stringify({ 
          error: 'Missing required fields: email and password are required' 
        }),
        { 
          status: 400, 
          headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
        }
      )
    }

    // Get Firebase Web API Key
    const firebaseWebApiKey = Deno.env.get('FIREBASE_WEB_API_KEY')
    
    if (!firebaseWebApiKey) {
      throw new Error('Firebase Web API Key not configured')
    }

    // Step 1: Authenticate with Firebase
    const firebaseResponse = await fetch(
      `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${firebaseWebApiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email,
          password,
          returnSecureToken: true,
        }),
      }
    )

    if (!firebaseResponse.ok) {
      const errorData = await firebaseResponse.json()
      return new Response(
        JSON.stringify({ 
          error: errorData.error?.message || 'Invalid login credentials' 
        }),
        { 
          status: 401, 
          headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
        }
      )
    }

    const firebaseUser = await firebaseResponse.json()

    // Step 2: Get user data from Supabase
    const supabaseClient = createClient(
      Deno.env.get('SUPABASE_URL') ?? '',
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? '',
      {
        auth: {
          autoRefreshToken: false,
          persistSession: false
        }
      }
    )

    const { data: dbUser, error: dbError } = await supabaseClient
      .from('users')
      .select('*')
      .eq('firebase_uid', firebaseUser.localId)
      .single()

    if (dbError || !dbUser) {
      return new Response(
        JSON.stringify({ 
          error: 'User not found in database' 
        }),
        { 
          status: 404, 
          headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
        }
      )
    }

    // Step 3: Return success response with user data and token
    return new Response(
      JSON.stringify({
        success: true,
        user: {
          id: dbUser.id,
          name: dbUser.name,
          email: dbUser.email,
          firebase_uid: dbUser.firebase_uid,
          created_at: dbUser.created_at,
        },
        firebase_token: firebaseUser.idToken,
        refresh_token: firebaseUser.refreshToken,
        expires_in: firebaseUser.expiresIn,
      }),
      { 
        status: 200, 
        headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
      }
    )

  } catch (error) {
    console.error('Login error:', error)
    
    return new Response(
      JSON.stringify({ 
        error: error.message || 'Internal server error during login' 
      }),
      { 
        status: 500, 
        headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
      }
    )
  }
})