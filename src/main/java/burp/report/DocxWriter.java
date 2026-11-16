package burp.report;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Minimal Office Open XML (.docx) writer — builds the WordprocessingML body with
 * direct run/paragraph formatting and zips it with the required package parts. No
 * external dependency (a .docx is just a ZIP of XML), so the extension jar stays light.
 *
 * @author Zahid Eroglu
 */
public class DocxWriter {

    private static final String DOC_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main";
    private final StringBuilder body = new StringBuilder();

    /** Heading: level 1..3 (size + colour scale down). */
    public DocxWriter heading(String text, int level) {
        int sz = level <= 1 ? 36 : level == 2 ? 28 : 24; // half-points => 18/14/12 pt
        String color = level <= 1 ? "1F3864" : level == 2 ? "2E5496" : "44546A";
        body.append("<w:p><w:pPr><w:spacing w:before=\"240\" w:after=\"80\"/></w:pPr>")
            .append("<w:r><w:rPr><w:b/><w:sz w:val=\"").append(sz).append("\"/><w:color w:val=\"").append(color)
            .append("\"/></w:rPr><w:t xml:space=\"preserve\">").append(esc(text)).append("</w:t></w:r></w:p>");
        return this;
    }

    public DocxWriter title(String text, String subtitle) {
        body.append("<w:p><w:pPr><w:jc w:val=\"center\"/><w:spacing w:before=\"1200\" w:after=\"120\"/></w:pPr>")
            .append("<w:r><w:rPr><w:b/><w:sz w:val=\"56\"/><w:color w:val=\"1F3864\"/></w:rPr>")
            .append("<w:t xml:space=\"preserve\">").append(esc(text)).append("</w:t></w:r></w:p>");
        if (subtitle != null) {
            body.append("<w:p><w:pPr><w:jc w:val=\"center\"/><w:spacing w:after=\"2400\"/></w:pPr>")
                .append("<w:r><w:rPr><w:sz w:val=\"28\"/><w:color w:val=\"595959\"/></w:rPr>")
                .append("<w:t xml:space=\"preserve\">").append(esc(subtitle)).append("</w:t></w:r></w:p>");
        }
        return this;
    }

    public DocxWriter paragraph(String text) {
        body.append("<w:p><w:pPr><w:spacing w:after=\"120\"/></w:pPr>")
            .append("<w:r><w:rPr><w:sz w:val=\"22\"/></w:rPr><w:t xml:space=\"preserve\">")
            .append(esc(text)).append("</w:t></w:r></w:p>");
        return this;
    }

    /** Bold "Key: " + normal value, one line. */
    public DocxWriter keyVal(String key, String value) {
        body.append("<w:p><w:pPr><w:spacing w:after=\"40\"/></w:pPr>")
            .append("<w:r><w:rPr><w:b/><w:sz w:val=\"22\"/></w:rPr><w:t xml:space=\"preserve\">")
            .append(esc(key)).append(": </w:t></w:r>")
            .append("<w:r><w:rPr><w:sz w:val=\"22\"/></w:rPr><w:t xml:space=\"preserve\">")
            .append(esc(value == null ? "" : value)).append("</w:t></w:r></w:p>");
        return this;
    }

    public DocxWriter bullet(String text) {
        body.append("<w:p><w:pPr><w:ind w:left=\"360\"/><w:spacing w:after=\"40\"/></w:pPr>")
            .append("<w:r><w:rPr><w:sz w:val=\"22\"/></w:rPr><w:t xml:space=\"preserve\">• ")
            .append(esc(text)).append("</w:t></w:r></w:p>");
        return this;
    }

    /** Monospace, shaded, multi-line block (request / curl / evidence). */
    public DocxWriter codeBlock(String text) {
        if (text == null) text = "";
        body.append("<w:p><w:pPr><w:shd w:val=\"clear\" w:fill=\"F2F2F2\"/><w:spacing w:after=\"120\"/></w:pPr>");
        String[] lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n", -1);
        for (int i = 0; i < lines.length; i++) {
            if (i > 50) { body.append("<w:r><w:rPr><w:rFonts w:ascii=\"Consolas\" w:hAnsi=\"Consolas\"/><w:sz w:val=\"18\"/></w:rPr><w:t>…</w:t></w:r>"); break; }
            body.append("<w:r><w:rPr><w:rFonts w:ascii=\"Consolas\" w:hAnsi=\"Consolas\"/><w:sz w:val=\"18\"/></w:rPr>")
                .append("<w:t xml:space=\"preserve\">").append(esc(lines[i])).append("</w:t>");
            if (i < lines.length - 1) body.append("<w:br/>");
            body.append("</w:r>");
        }
        body.append("</w:p>");
        return this;
    }

    /** Bordered table; first row is a shaded bold header. */
    public DocxWriter table(String[] headers, List<String[]> rows) {
        body.append("<w:tbl><w:tblPr><w:tblW w:w=\"5000\" w:type=\"pct\"/><w:tblBorders>")
            .append(border("top")).append(border("left")).append(border("bottom")).append(border("right"))
            .append(border("insideH")).append(border("insideV")).append("</w:tblBorders></w:tblPr>");
        body.append(row(headers, true));
        if (rows != null) for (String[] r : rows) body.append(row(r, false));
        body.append("</w:tbl>");
        body.append("<w:p><w:pPr><w:spacing w:after=\"120\"/></w:pPr></w:p>");
        return this;
    }

    public DocxWriter pageBreak() {
        body.append("<w:p><w:r><w:br w:type=\"page\"/></w:r></w:p>");
        return this;
    }

    public void save(File out) throws Exception {
        byte[] bytes = toBytes();
        try (FileOutputStream fos = new FileOutputStream(out)) { fos.write(bytes); }
    }

    public byte[] toBytes() throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ZipOutputStream zip = new ZipOutputStream(bos);
        put(zip, "[Content_Types].xml", CONTENT_TYPES);
        put(zip, "_rels/.rels", RELS);
        put(zip, "word/document.xml",
                "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
                + "<w:document xmlns:w=\"" + DOC_NS + "\"><w:body>" + body
                + "<w:sectPr><w:pgSz w:w=\"11906\" w:h=\"16838\"/>"
                + "<w:pgMar w:top=\"1134\" w:right=\"1134\" w:bottom=\"1134\" w:left=\"1134\"/></w:sectPr>"
                + "</w:body></w:document>");
        zip.close();
        return bos.toByteArray();
    }

    private String row(String[] cells, boolean header) {
        StringBuilder sb = new StringBuilder("<w:tr>");
        if (cells != null) for (String c : cells) {
            sb.append("<w:tc><w:tcPr>");
            if (header) sb.append("<w:shd w:val=\"clear\" w:fill=\"1F3864\"/>");
            sb.append("</w:tcPr><w:p><w:pPr><w:spacing w:after=\"20\"/></w:pPr><w:r><w:rPr><w:sz w:val=\"20\"/>");
            if (header) sb.append("<w:b/><w:color w:val=\"FFFFFF\"/>");
            sb.append("</w:rPr><w:t xml:space=\"preserve\">").append(esc(c == null ? "" : c)).append("</w:t></w:r></w:p></w:tc>");
        }
        return sb.append("</w:tr>").toString();
    }

    private String border(String side) {
        return "<w:" + side + " w:val=\"single\" w:sz=\"4\" w:color=\"BFBFBF\"/>";
    }

    private void put(ZipOutputStream zip, String name, String content) throws Exception {
        zip.putNextEntry(new ZipEntry(name));
        zip.write(content.getBytes(StandardCharsets.UTF_8));
        zip.closeEntry();
    }

    private static String esc(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '&': sb.append("&amp;"); break;
                case '<': sb.append("&lt;"); break;
                case '>': sb.append("&gt;"); break;
                case '"': sb.append("&quot;"); break;
                default:
                    // strip control chars that are invalid in XML
                    if (c >= 0x20 || c == '\t' || c == '\n' || c == '\r') sb.append(c);
            }
        }
        return sb.toString();
    }

    private static final String CONTENT_TYPES =
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
            + "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">"
            + "<Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>"
            + "<Default Extension=\"xml\" ContentType=\"application/xml\"/>"
            + "<Override PartName=\"/word/document.xml\" "
            + "ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/></Types>";

    private static final String RELS =
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
            + "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">"
            + "<Relationship Id=\"rId1\" "
            + "Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" "
            + "Target=\"word/document.xml\"/></Relationships>";
}
