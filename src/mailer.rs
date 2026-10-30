//! Alertes e-mail aux admins via SMTP. Sans `SMTP_HOST`, l'e-mail est seulement journalisé (mode dev).

use lettre::message::{header::ContentType, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use once_cell::sync::OnceCell;
use tracing::{error, info, warn};

struct SmtpConf {
    host: String,
    port: u16,
    user: String,
    pass: String,
    from: String,
    secure: bool,
}

fn conf() -> SmtpConf {
    let env = |k: &str| std::env::var(k).unwrap_or_default();
    let user = env("SMTP_USER");
    SmtpConf {
        host: env("SMTP_HOST"),
        port: env("SMTP_PORT").parse().unwrap_or(587),
        pass: env("SMTP_PASS"),
        from: Some(env("SMTP_FROM")).filter(|f| !f.is_empty()).unwrap_or_else(|| user.clone()),
        secure: env("SMTP_SECURE") == "true",
        user,
    }
}

static TRANSPORT: OnceCell<Option<(AsyncSmtpTransport<Tokio1Executor>, String)>> = OnceCell::new();

fn transport() -> Option<&'static (AsyncSmtpTransport<Tokio1Executor>, String)> {
    TRANSPORT
        .get_or_init(|| {
            let c = conf();
            if c.host.is_empty() {
                return None;
            }
            // secure=true → TLS implicite (465), sinon STARTTLS opportuniste comme nodemailer.
            let builder = if c.secure {
                AsyncSmtpTransport::<Tokio1Executor>::relay(&c.host)
            } else {
                AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&c.host)
            };
            let mut b = match builder {
                Ok(b) => b.port(c.port),
                Err(e) => {
                    error!("[Mailer] transport SMTP invalide : {e}");
                    return None;
                }
            };
            if !c.user.is_empty() {
                b = b.credentials(Credentials::new(c.user.clone(), c.pass.clone()));
            }
            Some((b.build(), c.from))
        })
        .as_ref()
}

/// Envoie un e-mail à une liste de destinataires (ne renvoie jamais d'erreur).
pub async fn send_mail(to: &[String], subject: &str, text: &str) {
    let Some((transport, from)) = transport().filter(|_| !to.is_empty()) else {
        warn!(subject = subject, to = ?to, "[Mailer] SMTP non configuré — email simulé en console");
        info!("[Mailer] SUJET: {subject}");
        info!("[Mailer] CORPS: {text}");
        return;
    };

    let build = || -> Result<Message, String> {
        let mut m = Message::builder().from(from.parse().map_err(|e| format!("{e}"))?).subject(subject);
        for t in to {
            m = m.to(t.parse().map_err(|e| format!("{e}"))?);
        }
        m.multipart(
            MultiPart::alternative()
                .singlepart(SinglePart::builder().header(ContentType::TEXT_PLAIN).body(text.to_string()))
                .singlepart(SinglePart::builder().header(ContentType::TEXT_HTML).body(text.replace('\n', "<br>"))),
        )
        .map_err(|e| format!("{e}"))
    };

    match build() {
        Ok(msg) => match transport.send(msg).await {
            Ok(_) => info!(to = ?to, "[Mailer] Email envoyé"),
            Err(e) => error!("[Mailer] Échec envoi email : {e}"),
        },
        Err(e) => error!("[Mailer] Échec envoi email : {e}"),
    }
}
