import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import type { Request } from 'express';
import * as bcrypt from 'bcrypt';

import { Session, SessionDocument } from '../../sessions/session.schema';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(
    @InjectModel(Session.name)
    private readonly sessionModel: Model<SessionDocument>,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: process.env.JWT_ACCESS_SECRET,
      passReqToCallback: true,
    });
  }

  async validate(req: Request, payload: any) {
    const token = ExtractJwt.fromAuthHeaderAsBearerToken()(req);

    if (!token) {
      throw new UnauthorizedException('Token missing');
    }

    const sessions = await this.sessionModel.find({
      userId: new Types.ObjectId(payload.sub),
      isActive: true,
    });

    for (const session of sessions) {
      const isMatch = await bcrypt.compare(token, session.token);
      if (isMatch) {
        return {
          userId: payload.sub,
          email: payload.email,
          role: payload.role,
          name: payload.name,
        };
      }
    }
    throw new UnauthorizedException('Session expired');
  }
}
