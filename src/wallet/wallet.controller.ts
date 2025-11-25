import { Controller, Post, Body, Logger } from '@nestjs/common';
import { WalletConnectService } from './wallet.service';

@Controller('wallet-connect')
export class WalletConnectController {
  private readonly logger = new Logger(WalletConnectController.name);

  constructor(private wc: WalletConnectService) {}

  // returns uri immediately (no wait)
  @Post('pair')
  async pair(@Body() body: { operationId?: string }) {
    const { uri } = await this.wc.createPairing(body?.operationId);
    return { wcUri: uri };
  }

  // pairs and waits for approval (blocks until user approves or timeout)
  @Post('pair-and-wait')
  async pairAndWait(@Body() body: { sessionId: string; timeoutMs?: number }) {
    const { sessionId, timeoutMs } = body;
    const { uri, approvalPromise } = await this.wc.pairAndApproveQr(sessionId, timeoutMs || undefined);

    // Immediately respond with uri and a promise result when ready
    // We block here until approvalPromise resolves or rejects (this is intentional for "pair-and-wait")
    try {
      const result = await approvalPromise;
      // result contains accessToken, user, topic
      return {
        wcUri: uri,
        approved: true,
        topic: result.topic,
        accessToken: result.accessToken,
        user: {
          id: result.user.id,
          walletAddress: result.user.walletAddress,
          fullName: result.user.fullName,
          role: result.user.role,
        },
      };
    } catch (err) {
      // timeout or error
      this.logger.error('pairAndWait failed', err);
      throw err;
    }
  }

  @Post('send')
  async send(@Body() dto: { topic: string; method: string; params: any[] }) {
    return await this.wc.sendRequest(dto.topic, dto.method, dto.params);
  }
}
