// src/auth/jwt.strategy.ts
import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private prisma: PrismaService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: process.env.JWT_SECRET || 'SUPER_SECRET_KEY',
    });
  }

  async validate(payload: any) {
    // Validate if user still exists
    const user = await this.prisma.user.findUnique({
      where: { id: payload.userId }
    });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    return { 
      userId: payload.userId,
      email: user.email,
      role: user.role
    };
  }
}