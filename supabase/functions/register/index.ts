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
    const { name, email, password } = await req.json()

    // Validate input
    if (!name || !email || !password) {
      return new Response(
        JSON.stringify({ 
          error: 'Missing required fields: name, email, and password are required' 
        }),
        { 
          status: 400, 
          headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
        }
      )
    }

    // Validate password length
    if (password.length < 6) {
      return new Response(
        JSON.stringify({ 
          error: 'Password must be at least 6 characters long' 
        }),
        { 
          status: 400, 
          headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
        }
      )
    }

    // Get Firebase Web API Key from service account
    const firebaseWebApiKey = Deno.env.get('FIREBASE_WEB_API_KEY')
    
    if (!firebaseWebApiKey) {
      throw new Error('Firebase Web API Key not configured')
    }

    // Step 1: Create user in Firebase using Web API
    const firebaseResponse = await fetch(
      `https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=${firebaseWebApiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email,
          password,
          displayName: name,
          returnSecureToken: true,
        }),
      }
    )

    if (!firebaseResponse.ok) {
      const errorData = await firebaseResponse.json()
      throw new Error(errorData.error?.message || 'Failed to create Firebase user')
    }

    const firebaseUser = await firebaseResponse.json()

    // Step 2: Initialize Supabase client with service role
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

    // Step 3: Save user to Supabase database
    const { data: dbUser, error: dbError } = await supabaseClient
      .from('users')
      .insert({
        name,
        email,
        firebase_uid: firebaseUser.localId,
      })
      .select()
      .single()

    if (dbError) {
      // If database insert fails, delete Firebase user (rollback)
      await fetch(
        `https://identitytoolkit.googleapis.com/v1/accounts:delete?key=${firebaseWebApiKey}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ idToken: firebaseUser.idToken }),
        }
      )
      throw new Error(`Database error: ${dbError.message}`)
    }

    // Step 4: Return success response
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
      }),
      { 
        status: 201, 
        headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
      }
    )

  } catch (error) {
    console.error('Registration error:', error)
    
    return new Response(
      JSON.stringify({ 
        error: error.message || 'Internal server error during registration' 
      }),
      { 
        status: 500, 
        headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
      }
    )
  }
})