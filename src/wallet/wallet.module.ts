import { Module } from '@nestjs/common';
import { WalletConnectController } from './wallet.controller';
import { WalletConnectService } from './wallet.service';
import { JwtService } from '@nestjs/jwt';
import { WalletService } from 'src/auth/walletService';

@Module({
  controllers: [WalletConnectController],
  providers: [WalletConnectService, WalletService, JwtService],
  exports: [WalletConnectService],
})
export class WalletModule {}
