//! Types de salon et règles d'écriture propres à chaque type.
//!
//! Liste identique à `servers/internal/servers/channel_kinds.go` et à
//! `Frontend-AlfyChat/src/components/alfy/guild/channel-kinds.ts`. Les 30 types
//! « à usage » réutilisent une vue existante (texte, forum, vocal, scène) ; les
//! types texte peuvent porter une règle, vérifiée ici à l'envoi d'un message.
//! Qui gère les messages du salon (MANAGE_MESSAGES) n'est jamais soumis aux règles.

use once_cell::sync::Lazy;
use regex::Regex;

/// Tous les types acceptés à la création / modification d'un salon.
pub const CHANNEL_TYPES: [&str; 46] = [
    // Types d'origine
    "text", "voice", "forum", "announcement", "stage", "category", "gallery", "poll", "suggestion", "doc", "counting", "vent", "thread", "media",
    "minigame", "trivia",
    // Texte
    "rules", "welcome", "changelog", "logs", "resources", "links", "memes", "art", "screenshots", "music", "clips", "questions", "oneword",
    "emoji", "code", "selfpromo", "focus", "commands", "introductions", "lfg",
    // Forum
    "support", "bugs", "feedback", "jobs", "wiki", "showcase",
    // Vocal et scène
    "listening", "gaming", "afk", "podcast",
];

/// Salons où l'on se connecte en vocal (et non où l'on écrit).
pub fn is_voice_kind(kind: &str) -> bool {
    matches!(kind, "voice" | "stage" | "listening" | "gaming" | "afk" | "podcast")
}

/// Règle d'écriture d'un type de salon texte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    /// Seule la modération publie (règlement, annonces automatiques…).
    ReadOnly,
    /// Une image ou un fichier joint est obligatoire.
    MediaOnly,
    /// Un lien est obligatoire.
    LinksOnly,
    /// Une image, un fichier ou un lien.
    MediaOrLinks,
    /// Le message doit être une question.
    Question,
    /// Un seul mot.
    OneWord,
    /// Uniquement des émojis.
    EmojiOnly,
    /// Un bloc de code (```) est obligatoire.
    Code,
    /// Uniquement des commandes de bot (/… ou !…).
    Commands,
}

pub fn rule_of(kind: &str) -> Option<Rule> {
    Some(match kind {
        "rules" | "welcome" | "changelog" | "logs" => Rule::ReadOnly,
        "memes" | "art" | "screenshots" => Rule::MediaOnly,
        "resources" | "links" | "music" => Rule::LinksOnly,
        "clips" => Rule::MediaOrLinks,
        "questions" => Rule::Question,
        "oneword" => Rule::OneWord,
        "emoji" => Rule::EmojiOnly,
        "code" => Rule::Code,
        "commands" => Rule::Commands,
        _ => return None,
    })
}

impl Rule {
    /// Code renvoyé au client (SERVER_MESSAGE_ERROR.rule) et message lisible.
    pub fn code(self) -> &'static str {
        match self {
            Rule::ReadOnly => "READ_ONLY",
            Rule::MediaOnly => "MEDIA_ONLY",
            Rule::LinksOnly => "LINKS_ONLY",
            Rule::MediaOrLinks => "MEDIA_OR_LINKS",
            Rule::Question => "QUESTION_ONLY",
            Rule::OneWord => "ONE_WORD",
            Rule::EmojiOnly => "EMOJI_ONLY",
            Rule::Code => "CODE_ONLY",
            Rule::Commands => "COMMANDS_ONLY",
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Rule::ReadOnly => "Seule la modération peut écrire dans ce salon.",
            Rule::MediaOnly => "Ce salon n’accepte que des images ou des fichiers.",
            Rule::LinksOnly => "Ce salon n’accepte que des messages contenant un lien.",
            Rule::MediaOrLinks => "Ce salon n’accepte que des médias ou des liens.",
            Rule::Question => "Ce salon est réservé aux questions (terminez par « ? »).",
            Rule::OneWord => "Un seul mot par message dans ce salon.",
            Rule::EmojiOnly => "Ce salon n’accepte que des émojis.",
            Rule::Code => "Ce salon attend un bloc de code (```).",
            Rule::Commands => "Ce salon est réservé aux commandes de bot (/… ou !…).",
        }
    }

    /// Le message respecte-t-il la règle ? `content` inclut les lignes de pièces jointes du client.
    pub fn allows(self, content: &str, has_attachments: bool) -> bool {
        let text = content.trim();
        let media = has_attachments || content.contains("[attach:img]") || content.contains("[attach:file]");
        let link = LINK_RE.is_match(content);
        match self {
            Rule::ReadOnly => false,
            Rule::MediaOnly => media,
            Rule::LinksOnly => link,
            Rule::MediaOrLinks => media || link,
            Rule::Question => text.ends_with('?') || text.ends_with('？'),
            Rule::OneWord => !text.is_empty() && !text.chars().any(char::is_whitespace) && text.chars().count() <= 40,
            Rule::EmojiOnly => !text.is_empty() && EMOJI_RE.is_match(text),
            Rule::Code => content.contains("```"),
            Rule::Commands => text.starts_with('/') || text.starts_with('!'),
        }
    }
}

static LINK_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"https?://\S+").unwrap());
/// Émojis Unicode (avec modificateurs et assemblages) ou émojis personnalisés `:nom:`.
static EMOJI_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(?:\s|\p{Extended_Pictographic}|\p{Emoji_Component}|\x{200D}|\x{FE0F}|:[A-Za-z0-9_]{2,32}:)+$").unwrap()
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules() {
        assert!(Rule::MediaOnly.allows("[attach:img]:https://x/y.webp", false));
        assert!(!Rule::MediaOnly.allows("salut", false));
        assert!(Rule::LinksOnly.allows("regarde https://alfychat.app", false));
        assert!(!Rule::LinksOnly.allows("pas de lien", false));
        assert!(Rule::Question.allows("Comment ça marche ?", false));
        assert!(!Rule::Question.allows("Bonjour", false));
        assert!(Rule::OneWord.allows("pomme", false));
        assert!(!Rule::OneWord.allows("deux mots", false));
        assert!(Rule::EmojiOnly.allows("😀 👍🏽 :party:", false));
        assert!(!Rule::EmojiOnly.allows("😀 salut", false));
        assert!(Rule::Code.allows("```js\nx\n```", false));
        assert!(Rule::Commands.allows("!ping", false));
        assert!(!Rule::Commands.allows("ping", false));
        assert!(!Rule::ReadOnly.allows("n'importe quoi", true));
    }

    #[test]
    fn kinds() {
        assert!(is_voice_kind("podcast") && is_voice_kind("voice") && !is_voice_kind("rules"));
        assert_eq!(rule_of("memes"), Some(Rule::MediaOnly));
        assert_eq!(rule_of("text"), None);
        assert!(CHANNEL_TYPES.contains(&"showcase"));
    }
}
