import type { Plugin, IMAdapter, IMMessage, IMOutgoingMessage } from '@yandu/types';
import axios from 'axios';
import { createHmac, createHash, createDecipheriv } from 'crypto';

export interface FeishuAdapterOptions {
  appId: string;
  appSecret: string;
  encryptKey?: string;
  verificationToken?: string;
}

interface FeishuTokenResponse {
  code: number;
  msg: string;
  tenant_access_token?: string;
  expire?: number;
}

interface FeishuSendResponse {
  code: number;
  msg: string;
  data?: {
    message_id: string;
  };
}

interface FeishuEventBody {
  uuid: string;
  event: FeishuMessageEvent;
  token?: string;
}

interface FeishuMessageEvent {
  sender: {
    sender_id: {
      open_id: string;
    };
  };
  message: {
    message_id: string;
    chat_id: string;
    content: string;
    create_time: string;
  };
}

function wrapApiError(err: unknown, prefix: string): Error {
  if (axios.isAxiosError(err)) {
    const status = err.response?.status;
    const detail =
      (err.response?.data as Record<string, string>)?.msg || err.message;
    return new Error(`${prefix}: ${detail} (HTTP ${status || 'N/A'})`);
  }
  return err instanceof Error ? err : new Error(String(err));
}

class FeishuAdapter implements IMAdapter {
  name = 'feishu';
  private options: FeishuAdapterOptions;
  private messageHandler?: (msg: IMMessage) => void;
  private tenantToken: string | null = null;
  private tokenExpiresAt = 0;
  private tokenRefreshPromise: Promise<string> | null = null;

  constructor(options: FeishuAdapterOptions) {
    this.options = options;
  }

  async initialize(): Promise<void> {
    await this.refreshTenantToken();
  }

  async send(message: IMOutgoingMessage): Promise<void> {
    const token = await this.getTenantToken();
    const url =
      'https://open.feishu.cn/open-apis/im/v1/messages?receive_id_type=chat_id';

    try {
      const response = await axios.post<FeishuSendResponse>(
        url,
        {
          receive_id: message.chatId,
          msg_type: 'text',
          content: JSON.stringify({ text: message.content }),
        },
        {
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json; charset=utf-8',
          },
        }
      );

      const data = response.data;
      if (data.code !== 0) {
        throw new Error(
          `Feishu send message failed: ${data.msg} (code: ${data.code})`
        );
      }
    } catch (err) {
      throw wrapApiError(err, 'Feishu API request failed');
    }
  }

  onMessage(handler: (msg: IMMessage) => void): void {
    this.messageHandler = handler;
  }

  handleEvent(
    event: unknown,
    signature?: string,
    timestamp?: string,
    nonce?: string
  ): void {
    const body = event as FeishuEventBody;

    this.verifyToken(body);
    this.verifySignature(body, signature, timestamp, nonce);

    const msgEvent = body.event;
    if (!msgEvent || !msgEvent.message) return;

    const content = this.decryptContent(msgEvent.message.content);
    const textContent = this.parseTextContent(content);

    this.messageHandler?.({
      id: msgEvent.message.message_id,
      content: textContent,
      senderId: msgEvent.sender?.sender_id?.open_id || 'unknown',
      chatId: msgEvent.message.chat_id,
      timestamp: msgEvent.message.create_time,
    });
  }

  private verifyToken(body: FeishuEventBody): void {
    if (
      this.options.verificationToken &&
      body.token !== undefined &&
      body.token !== this.options.verificationToken
    ) {
      throw new Error('Feishu event verification failed: invalid token');
    }
  }

  private verifySignature(
    body: FeishuEventBody,
    signature?: string,
    timestamp?: string,
    nonce?: string
  ): void {
    if (!signature || !timestamp || !nonce) return;

    const expected = this.computeSignature(
      timestamp,
      nonce,
      JSON.stringify(body)
    );
    if (expected !== signature) {
      throw new Error('Feishu event verification failed: invalid signature');
    }
  }

  private decryptContent(content: string): string {
    if (!this.options.encryptKey || !content.startsWith('"')) return content;

    try {
      const encrypted = JSON.parse(content).encrypt;
      return encrypted ? this.decrypt(encrypted) : content;
    } catch {
      return content;
    }
  }

  private parseTextContent(content: string): string {
    try {
      const parsed = JSON.parse(content);
      if (parsed && typeof parsed.text === 'string') return parsed.text;
    } catch {
      // 非 JSON 格式时直接使用
    }
    return content;
  }

  private async getTenantToken(): Promise<string> {
    if (this.tenantToken && Date.now() < this.tokenExpiresAt - 60_000) {
      return this.tenantToken;
    }
    if (!this.tokenRefreshPromise) {
      this.tokenRefreshPromise = this.refreshTenantToken().finally(() => {
        this.tokenRefreshPromise = null;
      });
    }
    return this.tokenRefreshPromise;
  }

  private async refreshTenantToken(): Promise<string> {
    try {
      const response = await axios.post<FeishuTokenResponse>(
        'https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal',
        {
          app_id: this.options.appId,
          app_secret: this.options.appSecret,
        },
        {
          headers: { 'Content-Type': 'application/json; charset=utf-8' },
        }
      );

      const data = response.data;
      if (data.code !== 0 || !data.tenant_access_token) {
        throw new Error(
          `Feishu token acquisition failed: ${data.msg} (code: ${data.code})`
        );
      }

      this.tenantToken = data.tenant_access_token;
      this.tokenExpiresAt = Date.now() + (data.expire ?? 7200) * 1000;
      return this.tenantToken;
    } catch (err) {
      throw wrapApiError(err, 'Feishu token request failed');
    }
  }

  private computeSignature(timestamp: string, nonce: string, body: string): string {
    const signString = `${timestamp}\n${nonce}\n${body}\n`;
    return createHmac('sha256', this.options.verificationToken!)
      .update(signString)
      .digest('hex');
  }

  private decrypt(encrypted: string): string {
    if (!this.options.encryptKey) return encrypted;

    const key = createHash('sha256').update(this.options.encryptKey).digest();
    const buffer = Buffer.from(encrypted, 'base64');
    const iv = buffer.slice(0, 16);
    const ciphertext = buffer.slice(16);

    const decipher = createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(ciphertext, undefined, 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  }
}

export default {
  name: '@yandu/plugin-im-feishu',
  version: '1.0.0',
  register(system) {
    const config = system.config;
    const appId = config.get<string>('im.feishu.appId');
    const appSecret = config.get<string>('im.feishu.appSecret');
    if (!appId || !appSecret) {
      console.warn('[plugin-im-feishu] No appId/appSecret configured, skipping registration');
      return;
    }
    const adapter = new FeishuAdapter({
      appId,
      appSecret,
      encryptKey: config.get<string>('im.feishu.encryptKey'),
      verificationToken: config.get<string>('im.feishu.verificationToken'),
    });
    system.capabilities.register(
      { type: 'im', id: adapter.name, name: 'Feishu Bot' },
      adapter
    );
  },
} satisfies Plugin;
