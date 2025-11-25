// src/auth/auth.controller.ts
import { 
  Controller, 
  Post, 
  Body, 
  Get, 
  Param, 
  UseGuards, 
  Req, 
  BadRequestException,
  Logger 
} from "@nestjs/common";
import { AuthService } from "./auth.service";
import { WalletConnectService } from "src/wallet/wallet.service";

@Controller("auth")
export class AuthController {
  private readonly logger = new Logger(AuthController.name);

  constructor(
    private auth: AuthService,
    private walletConnectService: WalletConnectService
  ) {}

  @Post("qr/pair-and-wait")
  async pairQrAndWait(@Body() body: { sessionId: string; timeoutMs?: number }) {
    const { sessionId, timeoutMs = 120000 } = body;

    try {
      const { uri, approvalPromise } = await this.walletConnectService.pairAndApproveQr(sessionId, timeoutMs);

      // Return the URI immediately for QR scanning
      return {
        wcUri: uri,
        message: "Scan this QR code with your wallet to login",
        sessionId: sessionId,
      };

    } catch (error: any) {
      this.logger.error('QR pair and wait failed', error);
      throw new BadRequestException(error.message);
    }
  }
}