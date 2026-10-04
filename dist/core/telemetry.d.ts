/**
 * NextGuard - Threat Intelligence, Device Fingerprinting & Forensics
 * Extracts detailed client forensic data (Device, OS, Browser, Geo-coordinates, ISP)
 * from incoming attack requests to assist with defensive monitoring and telemetry.
 */
import { RequestContext, ThreatType, InspectionVerdict } from '../types.js';
export interface GeoLocation {
    country?: string;
    countryCode?: string;
    city?: string;
    region?: string;
    coordinates?: {
        latitude: number;
        longitude: number;
    };
    isp?: string;
    timezone?: string;
}
export interface ClientDeviceFingerprint {
    deviceType: 'desktop' | 'mobile' | 'tablet' | 'bot_scanner' | 'unknown';
    os: string;
    browser: string;
    userAgent: string;
    isAutomatedTool: boolean;
}
export interface ThreatForensicRecord {
    eventId: string;
    timestamp: number;
    clientIp: string;
    geo: GeoLocation;
    client: ClientDeviceFingerprint;
    threat: {
        type: ThreatType;
        reason: string;
        severity: 'low' | 'medium' | 'high' | 'critical';
        statusCode: number;
        parameter?: string;
        location?: string;
    };
    request: {
        method: string;
        url: string;
        path: string;
        headers: Record<string, string>;
    };
}
export interface TelemetryConfig {
    enabled?: boolean;
    /** Max records to keep in in-memory ring buffer (default: 500) */
    maxHistory?: number;
    /** Webhook URL for alerting (Slack, Discord, or Custom SIEM API) */
    webhookUrl?: string;
    /**
     * Telegram Bot alert configuration.
     * Get your bot token from @BotFather and chat_id from @userinfobot.
     * @example { botToken: "123456:ABC...", chatId: "-100123456789" }
     */
    telegram?: {
        botToken: string;
        chatId: string;
        /** Only alert for these severity levels (default: all) */
        minSeverity?: 'low' | 'medium' | 'high' | 'critical';
        /** Custom message template (optional). Receives the ThreatForensicRecord */
        messageTemplate?: (record: ThreatForensicRecord) => string;
    };
    /** Custom geolocation resolver function (e.g. MaxMind or ip-api integration) */
    geoResolver?: (ip: string, headers: Record<string, string>) => Promise<GeoLocation> | GeoLocation;
}
/**
 * Parses user-agent strings into structured device and OS information
 */
export declare function parseDeviceFingerprint(ua?: string): ClientDeviceFingerprint;
/**
 * Extracts Geolocation data from reverse proxies (Cloudflare, Nginx, AWS CloudFront)
 * or fallback resolver
 */
export declare function extractGeoFromHeaders(headers: Record<string, string>): GeoLocation;
export declare class ThreatForensicsCollector {
    private enabled;
    private maxHistory;
    private webhookUrl?;
    private telegram?;
    private geoResolver?;
    private history;
    constructor(config?: TelemetryConfig | boolean);
    /**
     * Captures and analyzes forensic metadata for a blocked or monitored threat event
     */
    capture(verdict: InspectionVerdict, req: RequestContext): Promise<ThreatForensicRecord>;
    private sendWebhookAlert;
    /**
     * Sends a Telegram Bot alert via the Telegram Bot API.
     * Uses MarkdownV2 format with threat details, severity badge, and geo info.
     */
    private sendTelegramAlert;
    getHistory(limit?: number): ThreatForensicRecord[];
    clearHistory(): void;
}
//# sourceMappingURL=telemetry.d.ts.map