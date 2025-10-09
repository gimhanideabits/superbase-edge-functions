import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

export interface FirebaseUser {
  localId: string
  email: string
  emailVerified: boolean
  displayName?: string
  providerUserInfo?: any[]
  photoUrl?: string
  passwordHash?: string
  passwordUpdatedAt?: number
  validSince?: string
  disabled?: boolean
  lastLoginAt?: string
  createdAt?: string
  customAuth?: boolean
}

export interface MiddlewareContext {
  firebaseUser?: FirebaseUser
  supabaseClient: any
  url: URL
}

export const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Content-Type': 'application/json',
}


export function handleCorsPreflightRequest(req: Request): Response | null {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }
  return null
}


export function createErrorResponse(
  message: string, 
  status: number = 400,
  additionalHeaders: Record<string, string> = {}
): Response {
  return new Response(
    JSON.stringify({ error: message }),
    { 
      status, 
      headers: { ...corsHeaders, ...additionalHeaders } 
    }
  )
}


export function createSuccessResponse(
  data: any,
  status: number = 200,
  additionalHeaders: Record<string, string> = {}
): Response {
  return new Response(
    JSON.stringify(data),
    { 
      status, 
      headers: { ...corsHeaders, ...additionalHeaders } 
    }
  )
}


export function createSupabaseClient() {
  const supabaseUrl = Deno.env.get('SUPABASE_URL')
  const supabaseServiceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')
  
  if (!supabaseUrl || !supabaseServiceKey) {
    throw new Error('Missing Supabase configuration: SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required')
  }

  return createClient(supabaseUrl, supabaseServiceKey, {
    auth: {
      autoRefreshToken: false,
      persistSession: false
    }
  })
}


export async function verifyFirebaseToken(token: string): Promise<FirebaseUser> {
  const firebaseWebApiKey = Deno.env.get('FIREBASE_WEB_API_KEY')
  
  if (!firebaseWebApiKey) {
    throw new Error('Firebase Web API Key not configured')
  }

  try {
    const response = await fetch(
      `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${firebaseWebApiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ idToken: token }),
      }
    )

    if (!response.ok) {
      const errorData = await response.json()
      throw new Error(errorData.error?.message || 'Invalid or expired token')
    }

    const data = await response.json()
    
    if (!data.users || data.users.length === 0) {
      throw new Error('Invalid token: No user found')
    }

    return data.users[0] as FirebaseUser
  } catch (error) {
    throw new Error(`Firebase token verification failed: ${error.message}`)
  }
}

export async function extractAndVerifyToken(req: Request): Promise<FirebaseUser> {
  const authHeader = req.headers.get('Authorization')
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    throw new Error('Unauthorized: No valid Bearer token provided')
  }

  const token = authHeader.replace('Bearer ', '').trim()
  
  if (!token) {
    throw new Error('Unauthorized: Empty token provided')
  }

  return await verifyFirebaseToken(token)
}

export async function authenticateWithFirebase(email: string, password: string): Promise<any> {
  const firebaseWebApiKey = Deno.env.get('FIREBASE_WEB_API_KEY')
  
  if (!firebaseWebApiKey) {
    throw new Error('Firebase Web API Key not configured')
  }

  const response = await fetch(
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

  if (!response.ok) {
    const errorData = await response.json()
    throw new Error(errorData.error?.message || 'Invalid login credentials')
  }

  return await response.json()
}

export function validateRequiredFields(data: any, requiredFields: string[]): void {
  const missingFields = requiredFields.filter(field => !data[field])
  
  if (missingFields.length > 0) {
    throw new Error(`Missing required fields: ${missingFields.join(', ')}`)
  }
}


export function getRequiredQueryParam(url: URL, paramName: string): string {
  const value = url.searchParams.get(paramName)
  
  if (!value) {
    throw new Error(`Missing required query parameter: ${paramName}`)
  }
  
  return value
}


export async function withMiddleware(
  req: Request,
  handler: (req: Request, context: MiddlewareContext) => Promise<Response>,
  options: {
    requireAuth?: boolean
    validateEnv?: boolean
  } = {}
): Promise<Response> {
  try {
    // Handle CORS preflight
    const corsResponse = handleCorsPreflightRequest(req)
    if (corsResponse) return corsResponse

    // Validate environment variables if requested
    if (options.validateEnv) {
      const requiredEnvVars = ['SUPABASE_URL', 'SUPABASE_SERVICE_ROLE_KEY', 'FIREBASE_WEB_API_KEY']
      const missingEnvVars = requiredEnvVars.filter(envVar => !Deno.env.get(envVar))
      
      if (missingEnvVars.length > 0) {
        throw new Error(`Missing environment variables: ${missingEnvVars.join(', ')}`)
      }
    }

    // Create context
    const context: MiddlewareContext = {
      supabaseClient: createSupabaseClient(),
      url: new URL(req.url)
    }

    // Handle authentication if required
    if (options.requireAuth) {
      context.firebaseUser = await extractAndVerifyToken(req)
    }

    // Call the actual handler
    return await handler(req, context)

  } catch (error) {
    console.error('Middleware error:', error)
    
    // Return appropriate error response based on error type
    if (error.message.includes('Unauthorized')) {
      return createErrorResponse(error.message, 401)
    } else if (error.message.includes('Missing required')) {
      return createErrorResponse(error.message, 400)
    } else if (error.message.includes('not found') || error.message.includes('Not found')) {
      return createErrorResponse(error.message, 404)
    } else if (error.message.includes('Forbidden')) {
      return createErrorResponse(error.message, 403)
    } else {
      return createErrorResponse(
        error.message || 'Internal server error',
        500
      )
    }
  }
}


export function sanitizeUserData(user: any) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    firebase_uid: user.firebase_uid,
    created_at: user.created_at,
    updated_at: user.updated_at,
  }
}