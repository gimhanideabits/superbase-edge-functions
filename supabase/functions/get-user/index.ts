import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { 
  withMiddleware,
  getRequiredQueryParam,
  createSuccessResponse,
  sanitizeUserData,
  type MiddlewareContext
} from '../_shared/middleware.ts'

serve(async (req) => {
  return await withMiddleware(
    req,
    async (req: Request, context: MiddlewareContext) => {
      // Step 1: Get user ID from query parameters
      const userId = getRequiredQueryParam(context.url, 'id')

      // Step 2: Get user from Supabase database
      const { data: dbUser, error: dbError } = await context.supabaseClient
        .from('users')
        .select('*')
        .eq('id', userId)
        .single()

      if (dbError || !dbUser) {
        throw new Error('User not found')
      }

      // Step 3: Verify that the authenticated user matches the requested user
      // (Optional: Remove this check if you want any authenticated user to view any profile)
      if (dbUser.firebase_uid !== context.firebaseUser?.localId) {
        throw new Error('Forbidden: You can only access your own user data')
      }

      // Step 4: Return user data
      return createSuccessResponse({
        success: true,
        user: sanitizeUserData(dbUser),
        authenticated_as: {
          email: context.firebaseUser?.email,
          firebase_uid: context.firebaseUser?.localId,
        }
      })
    },
    {
      requireAuth: true,
      validateEnv: true
    }
  )
})