import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { PrismaService } from '../prisma/prisma.service';
import { JwtModule } from '@nestjs/jwt';
import { JwtStrategy } from './jwt.strategy';
import { WalletService } from './walletService';
import { WalletModule } from 'src/wallet/wallet.module';

@Module({
  imports: [
    JwtModule.register({
      secret: process.env.JWT_SECRET || 'SUPER_SECRET_KEY',
      signOptions: { expiresIn: '365d' }, // mobile apps usually long-lived tokens
    }),
    WalletModule
  ],
  controllers: [AuthController],
  providers: [AuthService, PrismaService, JwtStrategy, WalletService],
})
export class AuthModule {}
