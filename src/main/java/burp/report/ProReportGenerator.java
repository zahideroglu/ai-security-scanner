package burp.report;

import burp.Finding;
import burp.QwenAPIClient;

import org.json.JSONObject;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Professional .docx report generator: AI-written executive summary + per-finding
 * business-impact narrative (when AI is configured) on top of a structured template
 * (severity table, per-finding OWASP/CVSS/CWE/repro/evidence/remediation/references).
 * AI-flagged false positives are excluded from the detailed findings (counted only).
 *
 * @author Zahid Eroglu
 */
public class ProReportGenerator {

    private static final int AI_IMPACT_CAP = 40; // bound per-finding AI calls
    private final QwenAPIClient qwen;

    public ProReportGenerator(QwenAPIClient qwen) {
        this.qwen = qwen;
    }

    public void generate(List<Finding> all, File out) throws Exception {
        int fpCount = 0;
        List<Finding> real = new ArrayList<>();
        for (Finding f : (all == null ? new ArrayList<Finding>() : all)) {
            if (f == null) continue;
            if (f.isFalsePositive()) { fpCount++; continue; }
            real.add(f);
        }
        List<Finding> list = dedupAndSort(real);
        String date = new SimpleDateFormat("yyyy-MM-dd HH:mm").format(new Date());
        String target = guessTarget(list);

        DocxWriter d = new DocxWriter();
        d.title("AppSecHunter", "Güvenlik Değerlendirme Raporu");
        d.keyVal("Hedef", target);
        d.keyVal("Tarih", date);
        d.keyVal("Toplam bulgu", list.size() + (fpCount > 0 ? "  (+" + fpCount + " AI ile olası FP işaretli, hariç)" : ""));
        d.pageBreak();

        d.heading("Yönetici Özeti", 1);
        d.paragraph(aiExecutiveSummary(list, target, fpCount));

        d.heading("Önem Dağılımı", 2);
        d.table(new String[]{"Önem", "Adet"}, severityRows(list));
        d.pageBreak();

        d.heading("Bulgular", 1);
        int i = 1, aiUsed = 0;
        for (Finding f : list) {
            d.heading(i + ". " + safe(f.getType()) + "   [" + safe(f.getEffectiveSeverity()) + "]", 2);
            d.table(new String[]{"Alan", "Değer"}, metaRows(f));

            if (notEmpty(f.getDescription())) { d.heading("Açıklama", 3); d.paragraph(f.getDescription()); }

            if (aiUsed < AI_IMPACT_CAP) {
                String impact = aiBusinessImpact(f);
                if (notEmpty(impact)) { d.heading("İş Etkisi (AI)", 3); d.paragraph(impact); aiUsed++; }
            }
            if (notEmpty(f.getEvidence())) { d.heading("Kanıt", 3); d.paragraph(f.getEvidence()); }
            if (notEmpty(f.getHttpRequest())) { d.heading("İstek (Yeniden Üretim)", 3); d.codeBlock(f.getHttpRequest()); }
            if (notEmpty(f.getExploitation())) { d.heading("Notlar / AI Doğrulama", 3); d.paragraph(f.getExploitation()); }
            if (notEmpty(f.getRemediation())) { d.heading("Çözüm Önerisi", 3); d.paragraph(f.getRemediation()); }
            List<String> vsteps = f.getVerificationSteps();
            if (vsteps != null && !vsteps.isEmpty()) { d.heading("Doğrulama Adımları", 3); for (String vs : vsteps) d.bullet(vs); }
            List<String> refs = f.getReferences();
            if (refs != null && !refs.isEmpty()) { d.heading("Kaynaklar", 3); for (String r : refs) d.bullet(r); }
            d.pageBreak();
            i++;
        }
        d.save(out);
    }

    private List<Finding> dedupAndSort(List<Finding> in) {
        Map<String, Finding> best = new LinkedHashMap<>();
        for (Finding f : in) {
            String key = safe(f.getType()) + "|" + safe(f.getAffectedUrl()) + "|" + safe(f.getEvidence());
            Finding cur = best.get(key);
            if (cur == null || rank(f.getEffectiveSeverity()) > rank(cur.getSeverity())) best.put(key, f);
        }
        List<Finding> out = new ArrayList<>(best.values());
        out.sort((a, b) -> {
            int d = rank(b.getSeverity()) - rank(a.getSeverity());
            if (d != 0) return d;
            return Double.compare(b.getCvssScore(), a.getCvssScore());
        });
        return out;
    }

    private List<String[]> metaRows(Finding f) {
        List<String[]> r = new ArrayList<>();
        r.add(new String[]{"Önem", safe(f.getEffectiveSeverity())});
        r.add(new String[]{"CVSS", String.valueOf(f.getEffectiveCvss())});
        r.add(new String[]{"Öncelik", safe(f.getPriority())});
        r.add(new String[]{"OWASP", safe(f.getOwaspCategory())});
        if (notEmpty(f.getCweId())) r.add(new String[]{"CWE", f.getCweId()});
        r.add(new String[]{"Güven", String.format("%.0f%% (%s)", f.getConfidence() * 100, f.getConfidenceTier())});
        r.add(new String[]{"Kanıt", f.hasDeterministicEvidence() ? "Deterministik kanıt mevcut" : "Doğrulama gerekli"});
        if (notEmpty(f.getAffectedUrl())) r.add(new String[]{"URL", f.getAffectedUrl()});
        return r;
    }

    private List<String[]> severityRows(List<Finding> list) {
        Map<String, Integer> c = severityCounts(list);
        List<String[]> rows = new ArrayList<>();
        for (String s : new String[]{"Critical", "High", "Medium", "Low", "Info"}) {
            int n = c.getOrDefault(s, 0);
            if (n > 0) rows.add(new String[]{s, String.valueOf(n)});
        }
        return rows;
    }

    private Map<String, Integer> severityCounts(List<Finding> list) {
        Map<String, Integer> c = new LinkedHashMap<>();
        for (Finding f : list) {
            String s = norm(f.getEffectiveSeverity());
            c.put(s, c.getOrDefault(s, 0) + 1);
        }
        return c;
    }

    private String aiExecutiveSummary(List<Finding> list, String target, int fpCount) {
        String templated = "Bu değerlendirmede " + target + " üzerinde " + list.size() + " doğrulanmış bulgu tespit edildi"
                + (fpCount > 0 ? " (" + fpCount + " olası false-positive AI ile elendi)" : "") + ". "
                + "Önem dağılımı: " + severityCounts(list) + ". Öncelikli olarak yüksek önem dereceli erişim-kontrol ve "
                + "bilgi-ifşası bulguları giderilmelidir.";
        if (qwen == null) return templated;
        try {
            StringBuilder s = new StringBuilder();
            s.append("Hedef: ").append(target).append("\nDoğrulanmış bulgu: ").append(list.size())
             .append("\nÖnem dağılımı: ").append(severityCounts(list)).append("\nBulgu tipleri:\n");
            Set<String> types = new HashSet<>();
            int n = 0;
            for (Finding f : list) {
                if (types.add(f.getType())) {
                    s.append("- ").append(f.getType()).append(" (").append(f.getEffectiveSeverity()).append(")\n");
                    if (++n >= 25) break;
                }
            }
            List<QwenAPIClient.Message> m = new ArrayList<>();
            m.add(new QwenAPIClient.Message("system", "Sen kıdemli bir sızma testi uzmanısın. Profesyonel, net Türkçe "
                    + "yaz. Sadece düz metin, 2-3 paragraf yönetici özeti (madde işareti yok)."));
            m.add(new QwenAPIClient.Message("user", "Aşağıdaki bulgulara dayanarak bir YÖNETİCİ ÖZETİ yaz: genel risk "
                    + "durumu, en kritik temalar, iş etkisi ve öncelikli aksiyon önerisi. Akıcı paragraflar.\n\n" + s));
            JSONObject r = qwen.chatCompletion(m);
            String c = r.getJSONArray("choices").getJSONObject(0).getJSONObject("message").getString("content").trim();
            return c.isEmpty() ? templated : c;
        } catch (Exception e) {
            return templated;
        }
    }

    private String aiBusinessImpact(Finding f) {
        if (qwen == null) return "";
        String sev = norm(f.getEffectiveSeverity()).toLowerCase();
        if (!(sev.equals("critical") || sev.equals("high") || sev.equals("medium"))) return "";
        try {
            List<QwenAPIClient.Message> m = new ArrayList<>();
            m.add(new QwenAPIClient.Message("system", "Kıdemli sızma testi uzmanı. 1-2 cümle, Türkçe, iş etkisine odaklan."));
            m.add(new QwenAPIClient.Message("user", "Bu bulgunun İŞ ETKİSİNİ 1-2 cümlede yaz:\nTip: " + f.getType()
                    + "\nÖnem: " + f.getEffectiveSeverity() + "\nAçıklama: " + trunc(f.getDescription(), 400)
                    + "\nKanıt: " + trunc(f.getEvidence(), 200)));
            JSONObject r = qwen.chatCompletion(m);
            return r.getJSONArray("choices").getJSONObject(0).getJSONObject("message").getString("content").trim();
        } catch (Exception e) {
            return "";
        }
    }

    private String guessTarget(List<Finding> list) {
        for (Finding f : list) {
            String u = f.getAffectedUrl();
            if (notEmpty(u)) {
                try { return new java.net.URL(u).getHost(); } catch (Exception e) { return u; }
            }
        }
        return "(bilinmiyor)";
    }

    private int rank(String sev) {
        switch (norm(sev).toLowerCase()) {
            case "critical": return 5;
            case "high": return 4;
            case "medium": return 3;
            case "low": return 2;
            default: return 1;
        }
    }

    private String norm(String sev) {
        if (sev == null || sev.isEmpty()) return "Info";
        String s = sev.trim();
        return Character.toUpperCase(s.charAt(0)) + s.substring(1).toLowerCase();
    }

    private boolean notEmpty(String s) { return s != null && !s.trim().isEmpty(); }
    private String safe(String s) { return s == null ? "" : s; }
    private String trunc(String s, int n) { return s == null ? "" : (s.length() <= n ? s : s.substring(0, n)); }
}
