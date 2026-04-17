// ==========================================
// ALFYCHAT - GATEWAY MAILER
// Envoie des alertes email aux admins via SMTP.
// Si SMTP_HOST n'est pas configuré, log seulement (mode dev).
// ==========================================

import nodemailer from 'nodemailer';
import { logger } from './logger';

const SMTP_HOST     = process.env.SMTP_HOST     || '';
const SMTP_PORT     = parseInt(process.env.SMTP_PORT || '587');
const SMTP_USER     = process.env.SMTP_USER     || '';
const SMTP_PASS     = process.env.SMTP_PASS     || '';
const SMTP_FROM     = process.env.SMTP_FROM     || SMTP_USER;
const SMTP_SECURE   = process.env.SMTP_SECURE === 'true'; // true = 465, false = STARTTLS

let _transport: nodemailer.Transporter | null = null;

function getTransport(): nodemailer.Transporter | null {
  if (!SMTP_HOST) return null;
  if (!_transport) {
    _transport = nodemailer.createTransport({
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
export async function sendMail(opts: {
  to: string[];
  subject: string;
  text: string;
  html?: string;
}): Promise<void> {
  const transport = getTransport();

  if (!transport || opts.to.length === 0) {
    logger.warn({ subject: opts.subject, to: opts.to }, '[Mailer] SMTP non configuré — email simulé en console');
    logger.info(`[Mailer] SUJET: ${opts.subject}`);
    logger.info(`[Mailer] CORPS: ${opts.text}`);
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
    logger.info({ messageId: info.messageId, to: opts.to }, '[Mailer] Email envoyé');
  } catch (err) {
    logger.error({ err }, '[Mailer] Échec envoi email');
  }
}
