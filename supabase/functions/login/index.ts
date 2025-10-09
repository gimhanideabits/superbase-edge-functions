import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { 
  withMiddleware,
  authenticateWithFirebase,
  validateRequiredFields,
  createSuccessResponse,
  createErrorResponse,
  sanitizeUserData,
  type MiddlewareContext
} from '../_shared/middleware.ts'

serve(async (req) => {
  return await withMiddleware(
    req,
    async (req: Request, context: MiddlewareContext) => {
      // Parse request body
      const requestBody = await req.json()
      const { email, password } = requestBody

      // Validate required fields
      validateRequiredFields(requestBody, ['email', 'password'])

      // Step 1: Authenticate with Firebase
      const firebaseUser = await authenticateWithFirebase(email, password)

      // Step 2: Get user data from Supabase
      const { data: dbUser, error: dbError } = await context.supabaseClient
        .from('users')
        .select('*')
        .eq('firebase_uid', firebaseUser.localId)
        .single()

      if (dbError || !dbUser) {
        throw new Error('User not found in database')
      }

      // Step 3: Return success response with user data and token
      return createSuccessResponse({
        success: true,
        user: sanitizeUserData(dbUser),
        firebase_token: firebaseUser.idToken,
        refresh_token: firebaseUser.refreshToken,
        expires_in: firebaseUser.expiresIn,
      })
    },
    {
      requireAuth: false,
      validateEnv: true
    }
  )
})