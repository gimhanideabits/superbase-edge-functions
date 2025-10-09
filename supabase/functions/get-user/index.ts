import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

// CORS headers
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

// Verify Firebase token
async function verifyFirebaseToken(token: string): Promise<any> {
  const firebaseWebApiKey = Deno.env.get('FIREBASE_WEB_API_KEY')
  
  if (!firebaseWebApiKey) {
    throw new Error('Firebase Web API Key not configured')
  }

  // Verify the token with Firebase
  const response = await fetch(
    `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${firebaseWebApiKey}`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ idToken: token }),
    }
  )

  if (!response.ok) {
    throw new Error('Invalid or expired token')
  }

  const data = await response.json()
  
  if (!data.users || data.users.length === 0) {
    throw new Error('Invalid token')
  }

  return data.users[0]
}

serve(async (req) => {
  // Handle CORS preflight requests
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }

  try {
    // Step 1: Get and verify token from Authorization header
    const authHeader = req.headers.get('Authorization')
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return new Response(
        JSON.stringify({ 
          error: 'Unauthorized: No token provided' 
        }),
        { 
          status: 401, 
          headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
        }
      )
    }

    const token = authHeader.replace('Bearer ', '')

    // Step 2: Verify the Firebase token
    let firebaseUser
    try {
      firebaseUser = await verifyFirebaseToken(token)
    } catch (error) {
      return new Response(
        JSON.stringify({ 
          error: 'Unauthorized: Invalid token' 
        }),
        { 
          status: 401, 
          headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
        }
      )
    }

    // Step 3: Get user ID from query parameters
    const url = new URL(req.url)
    const userId = url.searchParams.get('id')

    if (!userId) {
      return new Response(
        JSON.stringify({ 
          error: 'Missing required parameter: id' 
        }),
        { 
          status: 400, 
          headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
        }
      )
    }

    // Step 4: Get user from Supabase database
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
      .eq('id', userId)
      .single()

    if (dbError || !dbUser) {
      return new Response(
        JSON.stringify({ 
          error: 'User not found' 
        }),
        { 
          status: 404, 
          headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
        }
      )
    }

    // Step 5: Verify that the authenticated user matches the requested user
    // (Optional: Remove this check if you want any authenticated user to view any profile)
    if (dbUser.firebase_uid !== firebaseUser.localId) {
      return new Response(
        JSON.stringify({ 
          error: 'Forbidden: You can only access your own user data' 
        }),
        { 
          status: 403, 
          headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
        }
      )
    }

    // Step 6: Return user data
    return new Response(
      JSON.stringify({
        success: true,
        user: {
          id: dbUser.id,
          name: dbUser.name,
          email: dbUser.email,
          firebase_uid: dbUser.firebase_uid,
          created_at: dbUser.created_at,
          updated_at: dbUser.updated_at,
        },
        authenticated_as: {
          email: firebaseUser.email,
          firebase_uid: firebaseUser.localId,
        }
      }),
      { 
        status: 200, 
        headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
      }
    )

  } catch (error) {
    console.error('Get user error:', error)
    
    return new Response(
      JSON.stringify({ 
        error: error.message || 'Internal server error' 
      }),
      { 
        status: 500, 
        headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
      }
    )
  }
})