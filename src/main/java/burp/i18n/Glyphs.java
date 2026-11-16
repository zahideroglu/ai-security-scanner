package burp.i18n;

/**
 * Font-aware glyph sanitiser. Several screens embed decorative emoji (🚀 ⚡ 🌐 🛡️ ⏳ ✓ …)
 * directly in their labels. When the running JVM's UI font has no glyph for a codepoint,
 * Swing paints a "tofu" box (□) instead — which is exactly what was happening on this user's
 * machine across every screen.
 *
 * <p>Rather than hand-strip ~250 call sites, we detect once whether the active Look-and-Feel
 * font can render emoji and, if not, strip the pictographic codepoints centrally
 * ({@link I18n#t(String)} routes through {@link #clean(String)}). Systems whose font
 * <em>can</em> render emoji keep them untouched.
 *
 * <p>Arrows (→ ← ↻) and typographic punctuation (— · •) are intentionally preserved: they appear
 * inside body/log text and almost always have glyphs.
 *
 * @author Zahid Eroglu
 */
public final class Glyphs {

    private Glyphs() {}

    // We ALWAYS strip emoji from UI text. Detecting "can this font show emoji?" via
    // Font.canDisplay() proved unreliable: for Swing's composite/logical fonts it reports a glyph
    // exists (through a fallback font) while the component's ACTUAL render font still paints □ tofu.
    // On this user's Burp, emoji AND ↻ rendered as □ even though canDisplay() said "ok". So we drop
    // the detection entirely and convey meaning with vector Icons (burp.Icons), ASCII markers
    // ([OK]/[X]) and color. (Emoji are decorative here; nothing functional is lost.)
    private static final boolean EMOJI_OK = false;

    /** True when the active UI font can render emoji (so callers may keep their glyphs). */
    public static boolean emojiOk() {
        return EMOJI_OK;
    }

    /** Pass marker: "✓" on emoji-capable fonts, else a plain "[OK]" tag (no tofu). */
    public static String ok() {
        return EMOJI_OK ? "✓" : "[OK]";
    }

    /** Fail marker: "✗" on emoji-capable fonts, else a plain "[X]" tag (no tofu). */
    public static String fail() {
        return EMOJI_OK ? "✗" : "[X]";
    }

    /**
     * Strip pictographic/emoji codepoints when the font can't render them, collapsing the
     * whitespace the removal leaves behind. No-op when emoji are supported or input is blank.
     */
    public static String clean(String s) {
        if (s == null || s.isEmpty() || EMOJI_OK) return s;
        if (!hasPictograph(s)) return s;

        StringBuilder sb = new StringBuilder(s.length());
        int i = 0;
        while (i < s.length()) {
            int cp = s.codePointAt(i);
            int cc = Character.charCount(cp);
            if (!isPictograph(cp)) sb.appendCodePoint(cp);
            i += cc;
        }
        // Collapse spaces/tabs the stripped glyphs left behind, and trim line-leading/trailing gaps.
        return sb.toString()
                .replaceAll("[ \\t]{2,}", " ")
                .replaceAll("(?m)^[ \\t]+", "")
                .replaceAll("[ \\t]+$", "")
                .trim();
    }

    private static boolean hasPictograph(String s) {
        for (int i = 0; i < s.length(); ) {
            int cp = s.codePointAt(i);
            if (isPictograph(cp)) return true;
            i += Character.charCount(cp);
        }
        return false;
    }

    /**
     * Emoji / pictographic ranges. Deliberately excludes the Arrows block (U+2190–U+21FF) and
     * common punctuation so body text ("a → b", "—", "·") survives intact.
     */
    private static boolean isPictograph(int cp) {
        return (cp >= 0x1F000 && cp <= 0x1FAFF)   // emoji, pictographs, supplemental symbols
            || (cp >= 0x2600  && cp <= 0x26FF)    // miscellaneous symbols (⚡ ☀ ⛔ …)
            || (cp >= 0x2700  && cp <= 0x27BF)    // dingbats (✂ ✅ ✓ ✗ …)
            || (cp >= 0x2B00  && cp <= 0x2BFF)    // misc symbols & arrows (⭐ ⬆ …)
            || (cp >= 0x2300  && cp <= 0x23FF)    // technical (⌛ ⏳ ⏸ ⏯ …)
            || (cp >= 0xFE00  && cp <= 0xFE0F)    // variation selectors
            || cp == 0x20E3;                      // combining enclosing keycap
    }
}
