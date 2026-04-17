/**
 * Envoie un email à une liste de destinataires.
 * Si SMTP non configuré, log l'email dans la console (mode dev).
 */
export declare function sendMail(opts: {
    to: string[];
    subject: string;
    text: string;
    html?: string;
}): Promise<void>;
//# sourceMappingURL=mailer.d.ts.map