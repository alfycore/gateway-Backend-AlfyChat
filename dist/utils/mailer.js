"use strict";
// ==========================================
// ALFYCHAT - GATEWAY MAILER
// Envoie des alertes email aux admins via SMTP.
// Si SMTP_HOST n'est pas configuré, log seulement (mode dev).
// ==========================================
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.sendMail = sendMail;
const nodemailer_1 = __importDefault(require("nodemailer"));
const logger_1 = require("./logger");
const SMTP_HOST = process.env.SMTP_HOST || '';
const SMTP_PORT = parseInt(process.env.SMTP_PORT || '587');
const SMTP_USER = process.env.SMTP_USER || '';
const SMTP_PASS = process.env.SMTP_PASS || '';
const SMTP_FROM = process.env.SMTP_FROM || SMTP_USER;
const SMTP_SECURE = process.env.SMTP_SECURE === 'true'; // true = 465, false = STARTTLS
let _transport = null;
function getTransport() {
    if (!SMTP_HOST)
        return null;
    if (!_transport) {
        _transport = nodemailer_1.default.createTransport({
            host: SMTP_HOST,
            port: SMTP_PORT,
            secure: SMTP_SECURE,
            auth: SMTP_USER ? { user: SMTP_USER, pass: SMTP_PASS } : undefined,
        });
    }
    return _transport;
}
/**
 * Envoie un email à une liste de destinataires.
 * Si SMTP non configuré, log l'email dans la console (mode dev).
 */
async function sendMail(opts) {
    const transport = getTransport();
    if (!transport || opts.to.length === 0) {
        logger_1.logger.warn({ subject: opts.subject, to: opts.to }, '[Mailer] SMTP non configuré — email simulé en console');
        logger_1.logger.info(`[Mailer] SUJET: ${opts.subject}`);
        logger_1.logger.info(`[Mailer] CORPS: ${opts.text}`);
        return;
    }
    try {
        const info = await transport.sendMail({
            from: SMTP_FROM,
            to: opts.to.join(', '),
            subject: opts.subject,
            text: opts.text,
            html: opts.html || opts.text.replace(/\n/g, '<br>'),
        });
        logger_1.logger.info({ messageId: info.messageId, to: opts.to }, '[Mailer] Email envoyé');
    }
    catch (err) {
        logger_1.logger.error({ err }, '[Mailer] Échec envoi email');
    }
}
//# sourceMappingURL=mailer.js.map