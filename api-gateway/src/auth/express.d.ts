// This file augments the Express Request type to include the user property populated by Passport
import { SessionJwtPayload } from './strategies/jwt.strategy';

declare module 'express-serve-static-core' {
  interface Request {
    user?: SessionJwtPayload;
  }
}
